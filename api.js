// API utilities
class ApiClient {
  constructor() {
    this.baseUrl = '';
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    if (auth.isAuthenticated() && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${auth.token}`;
    }

    try {
      const response = await fetch(url, config);
      
      if (response.status === 401) {
        auth.logout();
        return null;
      }

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // User endpoints
  async getUserProfile() {
    return this.request('/api/user/profile');
  }

  async getUserStats() {
    return this.request('/api/user/stats');
  }

  // Items endpoints
  async getItems(filters = {}) {
    const params = new URLSearchParams(filters);
    return this.request(`/api/items?${params}`);
  }

  async getUserItems() {
    return this.request('/api/items/user');
  }

  async createItem(formData) {
    return this.request('/api/items', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${auth.token}`
      },
      body: formData
    });
  }

  async deleteItem(itemId) {
    return this.request(`/api/items/${itemId}`, {
      method: 'DELETE'
    });
  }

  // Swaps endpoints
  async getUserSwaps() {
    return this.request('/api/swaps/user');
  }

  async createSwap(ownerItemId, requesterItemId) {
    return this.request('/api/swaps', {
      method: 'POST',
      body: JSON.stringify({ ownerItemId, requesterItemId })
    });
  }
}

// Global API client instance
const api = new ApiClient();