const request = require('supertest');
const path = require('path');
const app = require('../src/app');
const { setupTestDB } = require('./setup');

setupTestDB();

describe('Email Upload & Analysis Module Tests (/api/email)', () => {
  const phishingEmlPath = path.join(__dirname, 'fixtures', 'phishing_email.eml');

  describe('POST /api/email/upload', () => {
    it('should parse an uploaded .eml file and return extracted metadata', async () => {
      const res = await request(app)
        .post('/api/email/upload')
        .attach('email_file', phishingEmlPath);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('emailId');
      expect(res.body.data.preview.subject).toContain('PayPal');
      expect(res.body.data.preview.extractedData.headers.spf).toBe('fail');
      expect(res.body.data.preview.extractedData.urls.length).toBeGreaterThan(0);
    });

    it('should parse raw email text body', async () => {
      const raw = `From: boss@corp.com\nTo: emp@corp.com\nSubject: Wire Transfer\n\nUrgent please process wire transfer today.`;
      const res = await request(app)
        .post('/api/email/upload')
        .send({ rawEmail: raw });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.preview.subject).toBe('Wire Transfer');
    });
  });

  describe('POST /api/email/analyze', () => {
    it('should perform end-to-end multi-vector analysis and return threat report', async () => {
      const res = await request(app)
        .post('/api/email/analyze')
        .attach('email_file', phishingEmlPath);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('reportId');
      expect(res.body.data.verdict).toBe('phishing');
      expect(res.body.data.riskScore).toBeGreaterThanOrEqual(70);
      expect(res.body.data.aiAnalysis.reasons.length).toBeGreaterThan(0);
      expect(res.body.data.recommendations.length).toBeGreaterThan(0);
    });
  });
});
