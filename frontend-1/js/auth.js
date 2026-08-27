/**
 * Authentication and Session Management
 */

const AuthManager = {
  // Check if current user is logged in
  getUser() {
    try {
      const userStr = localStorage.getItem('sih_user');
      if (userStr) return JSON.parse(userStr);
    } catch (e) {
      console.error("Failed to parse user session", e);
    }
    // Default fallback demo user for seamless preview
    return {
      name: "Security Analyst",
      email: "soc-admin@acme-corp.com",
      role: "Lead SOC Analyst",
      avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80"
    };
  },

  isLoggedIn() {
    return !!localStorage.getItem('sih_auth_token') || !!localStorage.getItem('sih_user');
  },

  requireAuth() {
    if (!this.isLoggedIn()) {
      // Set temporary demo session if visiting directly for easy evaluation
      const demoUser = {
        name: "Security Analyst",
        email: "soc-admin@acme-corp.com",
        role: "Lead SOC Analyst",
        avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        token: "demo_token"
      };
      localStorage.setItem('sih_user', JSON.stringify(demoUser));
    }
  },

  async handleLogin(event) {
    event.preventDefault();
    const form = event.target;
    const email = form.email.value.trim();
    const password = form.password.value;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;

    try {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span class="inline-block animate-spin mr-2">⟳</span> Authenticating...`;

      await window.api.login(email, password);
      
      if (window.Toast) {
        window.Toast.show("Authentication Successful! Redirecting to SOC Dashboard...", "success");
      }
      setTimeout(() => {
        window.location.href = "index.html";
      }, 700);
    } catch (error) {
      if (window.Toast) {
        window.Toast.show(error.message || "Failed to log in", "danger");
      } else {
        alert(error.message);
      }
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalText;
    }
  },

  async handleSignup(event) {
    event.preventDefault();
    const form = event.target;
    const name = form.name.value.trim();
    const email = form.email.value.trim();
    const role = form.role ? form.role.value : "SOC Analyst";
    const password = form.password.value;
    const confirmPassword = form.confirmPassword.value;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;

    if (password !== confirmPassword) {
      if (window.Toast) window.Toast.show("Passwords do not match!", "warning");
      else alert("Passwords do not match!");
      return;
    }

    try {
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span class="inline-block animate-spin mr-2">⟳</span> Provisioning Account...`;

      await window.api.signup({ name, email, password, confirmPassword, role });

      if (window.Toast) {
        window.Toast.show("Account registered successfully! Redirecting to SOC...", "success");
      }
      setTimeout(() => {
        window.location.href = "index.html";
      }, 700);
    } catch (error) {
      if (window.Toast) {
        window.Toast.show(error.message || "Signup failed", "danger");
      } else {
        alert(error.message);
      }
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalText;
    }
  },

  async logout() {
    await window.api.logout();
    if (window.Toast) {
      window.Toast.show("Logged out successfully.", "info");
    }
    setTimeout(() => {
      window.location.href = "login.html";
    }, 400);
  }
};

window.AuthManager = AuthManager;
