const request = require('supertest');
const app = require('../src/app');
const { setupTestDB } = require('./setup');

setupTestDB();

describe('AI & Multi-Vector Engine Tests', () => {
  describe('POST /api/ai/predict', () => {
    it('should classify urgent phishing email payload with reasons', async () => {
      const res = await request(app)
        .post('/api/ai/predict')
        .send({
          subject: 'Urgent: Verify bank account within 24 hours',
          body: 'Your account is suspended. Click here to confirm identity: http://fake-login.xyz',
          sender: 'security@fake-bank.xyz',
          headers: { spf: 'fail', dkim: 'fail' },
          urls: ['http://fake-login.xyz/login']
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.class).toBe('phishing');
      expect(res.body.data.risk_score).toBeGreaterThan(60);
      expect(res.body.data.reasons.length).toBeGreaterThan(0);
    });

    it('should classify legitimate emails as safe', async () => {
      const res = await request(app)
        .post('/api/ai/predict')
        .send({
          subject: 'Meeting notes from today',
          body: 'Here are the minutes of our quarterly review.',
          sender: 'colleague@company.com',
          headers: { spf: 'pass', dkim: 'pass' },
          urls: []
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.data.class).toBe('safe');
      expect(res.body.data.risk_score).toBeLessThan(30);
    });
  });

  describe('GET /api/sender-analysis/:email', () => {
    it('should identify brand spoofing and calculate risk', async () => {
      const res = await request(app)
        .get('/api/sender-analysis/service@paypal-security-alert.com?spf=fail');

      expect(res.statusCode).toBe(200);
      expect(res.body.data.senderDomain).toBe('paypal-security-alert.com');
      expect(res.body.data.isBrandImpersonation).toBe(true);
      expect(res.body.data.riskScore).toBeGreaterThanOrEqual(60);
    });
  });

  describe('POST /api/url/analyze', () => {
    it('should flag shorteners and IP URLs as suspicious/malicious', async () => {
      const res = await request(app)
        .post('/api/url/analyze')
        .send({
          urls: [
            'http://bit.ly/3x8f1-login',
            'http://192.168.1.50/malware.exe',
            'https://google.com'
          ]
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.data.totalUrls).toBe(3);
      expect(res.body.data.maliciousCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe('POST /api/attachment/analyze', () => {
    it('should flag executable and double extensions as critical', async () => {
      const res = await request(app)
        .post('/api/attachment/analyze')
        .send({
          attachments: [
            { filename: 'Statement_2026.pdf.exe', size: 45000 },
            { filename: 'report.docx', size: 12000 }
          ]
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.data.results[0].threatLevel).toBe('Critical');
      expect(res.body.data.results[0].hasDoubleExtension).toBe(true);
      expect(res.body.data.threatsFound).toBe(1);
    });
  });
});
