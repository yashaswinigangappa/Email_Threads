const request = require('supertest');
const path = require('path');
const app = require('../src/app');
const { setupTestDB } = require('./setup');

setupTestDB();

describe('Threat Report & History Tests', () => {
  const phishingEmlPath = path.join(__dirname, 'fixtures', 'phishing_email.eml');
  let createdReportId;

  beforeEach(async () => {
    const res = await request(app)
      .post('/api/email/analyze')
      .attach('email_file', phishingEmlPath);

    createdReportId = res.body.data.reportId;
  });

  describe('GET /api/report/:id', () => {
    it('should retrieve a detailed report by ID', async () => {
      const res = await request(app).get(`/api/report/${createdReportId}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.verdict).toBe('phishing');
      expect(res.body.data.indicatorsOfCompromise).toBeDefined();
    });
  });

  describe('GET /api/report/download/:id', () => {
    it('should generate and stream a downloadable PDF report', async () => {
      const res = await request(app).get(`/api/report/download/${createdReportId}`);

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain('attachment; filename="Threat_Report_');
      expect(res.body).toBeDefined();
    });
  });

  describe('GET /api/history & DELETE /api/history/:id', () => {
    it('should return paginated history of scans', async () => {
      const res = await request(app).get('/api/history?page=1&limit=10');

      expect(res.statusCode).toBe(200);
      expect(res.body.data.history.length).toBeGreaterThan(0);
      expect(res.body.data.pagination.totalRecords).toBeGreaterThan(0);
    });

    it('should delete a history item by ID', async () => {
      const res = await request(app).delete(`/api/history/${createdReportId}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);

      const checkRes = await request(app).get(`/api/report/${createdReportId}`);
      expect(checkRes.statusCode).toBe(404);
    });
  });
});
