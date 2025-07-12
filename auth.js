// Authentication utilities
class AuthManager {
  constructor() {
    this.token = localStorage.getItem('authToken');
    this.user = JSON.parse(localStorage.getItem('user') || 'null');
  }

  isAuthenticated() {
    return !!this.token;
  }

  async login(email, password, rememberMe = false) {
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, rememberMe })
      });

      const data = await response.json();

      if (response.ok) {
        this.token = data.token;
        this.user = data.user;
        
        if (rememberMe) {
          localStorage.setItem('authToken', data.token);
          localStorage.setItem('user', JSON.stringify(data.user));
        } else {
          sessionStorage.setItem('authToken', data.token);
          sessionStorage.setItem('user', JSON.stringify(data.user));
        }
        
        return { success: true, user: data.user };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      return { success: false, message: 'Network error. Please try again.' };
    }
  }

  async signup(name, email, password) {
    try {
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, email, password })
      });

      const data = await response.json();

      if (response.ok) {
        this.token = data.token;
        this.user = data.user;
        
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        
        return { success: true, user: data.user };
      } else {
        return { success: false, message: data.message };
      }
    } catch (error) {
      return { success: false, message: 'Network error. Please try again.' };
    }
  }

  logout() {
    this.token = null;
    this.user = null;
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    sessionStorage.removeItem('authToken');
    sessionStorage.removeItem('user');
    window.location.href = '/';
  }

  async validateToken() {
    if (!this.token) return false;

    try {
      const response = await fetch('/api/validate-token', {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      if (response.ok) {
        return true;
      } else {
        this.logout();
        return false;
      }
    } catch (error) {
      this.logout();
      return false;
    }
  }

  getAuthHeaders() {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  }

  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  }
}

// Global auth manager instance
const auth = new AuthManager();

// Check authentication on page load
document.addEventListener('DOMContentLoaded', async () => {
  // Get current page
  const currentPage = window.location.pathname;
  
  // Pages that require authentication
  const protectedPages = ['/profile', '/new-item'];
  
  // Pages that should redirect if already authenticated
  const authPages = ['/login', '/signup'];
  
  if (auth.isAuthenticated()) {
    const isValid = await auth.validateToken();
    
    if (isValid && authPages.includes(currentPage)) {
      // Redirect to profile if already logged in
      window.location.href = '/profile';
    } else if (!isValid && protectedPages.includes(currentPage)) {
      // Redirect to login if token is invalid
      window.location.href = '/login';
    }
  } else if (protectedPages.includes(currentPage)) {
    // Redirect to login if not authenticated
    window.location.href = '/login';
  }
});