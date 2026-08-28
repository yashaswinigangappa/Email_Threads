const request = require('supertest');
const app = require('../src/app');
const { setupTestDB } = require('./setup');
const User = require('../src/models/User');

setupTestDB();

describe('Authentication Module Tests (/api/auth)', () => {
  const testUser = {
    name: 'Test Analyst',
    email: 'analyst_test@example.com',
    password: 'Password123!'
  };

  describe('POST /api/auth/signup', () => {
    it('should successfully register a new user and return JWT token', async () => {
      const res = await request(app)
        .post('/api/auth/signup')
        .send(testUser);

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
      expect(res.body.data.user.email).toBe(testUser.email.toLowerCase());
      expect(res.body.data.user).toHaveProperty('apiKey');
    });

    it('should reject duplicate email registrations', async () => {
      await request(app).post('/api/auth/signup').send(testUser);

      const res = await request(app)
        .post('/api/auth/signup')
        .send(testUser);

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
    });

    it('should validate missing required fields', async () => {
      const res = await request(app)
        .post('/api/auth/signup')
        .send({ email: 'bad@email.com' });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await request(app).post('/api/auth/signup').send(testUser);
    });

    it('should authenticate user with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
    });

    it('should reject incorrect password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword!'
        });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/auth/me & API Key Access', () => {
    let token;
    let apiKey;

    beforeEach(async () => {
      const signupRes = await request(app).post('/api/auth/signup').send({
        name: 'Profile User',
        email: 'profile_test@example.com',
        password: 'Password123!'
      });
      token = signupRes.body.data.token;
      apiKey = signupRes.body.data.user.apiKey;
    });

    it('should retrieve user profile with Bearer Token', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.data.email).toBe('profile_test@example.com');
    });

    it('should authenticate with x-api-key header', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('x-api-key', apiKey);

      expect(res.statusCode).toBe(200);
      expect(res.body.data.email).toBe('profile_test@example.com');
    });
  });
});
