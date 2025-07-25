import React, { useState, useEffect } from 'react';
import { getProfile } from '../services/api';
import { showToast } from '../utils/helpers';

interface ProfileData {
  email: string;
  last_login: string | null;
  created_at: string | null;
}

const Profile: React.FC = () => {
  const [profileData, setProfileData] = useState<ProfileData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Check if user is authenticated
      const token = localStorage.getItem('jwt');
      if (!token) {
        setError('Please authenticate first to view your profile.');
        setLoading(false);
        return;
      }
      
      const data = await getProfile();
      setProfileData(data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load profile';
      setError(errorMessage);
      showToast(errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    try {
      const date = new Date(dateString);
      return date.toLocaleString();
    } catch {
      return dateString;
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`${label} copied to clipboard!`, 'success');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-slate-600 dark:text-slate-400">Loading profile...</p>
        </div>
      </div>
    );
  }

  if (error) {
    const isAuthError = error.includes('authenticate') || error.includes('token') || error.includes('Authorization');
    
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 flex items-center justify-center">
        <div className="text-center">
          <div className="bg-red-100 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6 max-w-md">
            <h2 className="text-xl font-semibold text-red-800 dark:text-red-200 mb-2">
              {isAuthError ? 'Authentication Required' : 'Error Loading Profile'}
            </h2>
            <p className="text-red-600 dark:text-red-300 mb-4">{error}</p>
            {isAuthError ? (
              <p className="text-blue-600 dark:text-blue-300 text-sm mb-4">
                Please go to the Dashboard and authenticate with your email address.
              </p>
            ) : (
              <button
                onClick={fetchProfile}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                Try Again
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="profile-card">
          <div className="profile-avatar" style={{ margin: '0 auto 12px auto' }}>
            <svg width="48" height="48" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
            </svg>
          </div>
          <h2 className="profile-title" style={{ textAlign: 'center', marginBottom: 24 }}>User Profile</h2>
          <div className="profile-info-list">
            <div className="profile-info-item">
              <span className="profile-info-icon" aria-label="Email">
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12H8m8 0a4 4 0 11-8 0 4 4 0 018 0zm2 4v1a2 2 0 01-2 2H6a2 2 0 01-2-2v-1" />
                </svg>
              </span>
              <span className="profile-info-label">Email Address</span>
              <span className="profile-info-value">{profileData?.email}</span>
              <button
                onClick={() => copyToClipboard(profileData?.email || '', 'Email')}
                className="profile-copy-icon-btn"
                title="Copy email"
                aria-label="Copy email"
              >
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              </button>
            </div>
            <div className="profile-info-item">
              <span className="profile-info-icon" aria-label="Last Login">
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </span>
              <span className="profile-info-label">Last Login</span>
              <span className="profile-info-value">{formatDate(profileData?.last_login || null)}</span>
            </div>
            <div className="profile-info-item">
              <span className="profile-info-icon" aria-label="Account Created">
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              </span>
              <span className="profile-info-label">Account Created</span>
              <span className="profile-info-value">{formatDate(profileData?.created_at || null)}</span>
            </div>
            <div className="profile-info-item">
              <span className="profile-info-icon" aria-label="Passwordless Authentication">
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </span>
              <span className="profile-info-label">Passwordless Authentication</span>
              <span className="profile-info-value" style={{ fontWeight: 400 }}>
                Your account uses ECC-based passwordless authentication for enhanced security.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile; 