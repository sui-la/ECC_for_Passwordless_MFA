import React, { useState, useEffect } from 'react';
import { sendSecureMessage, receiveSecureMessages, deleteSecureMessage, updateMessageEncryption } from '../services/api';
import { aesGcmEncryptWithMessageKey, aesGcmDecryptWithMessageKey } from '../services/crypto';
import { getValidSessionSecret } from '../services/storage';

interface Props {
  showToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  onReAuthenticate?: () => void;
  currentUserEmail?: string;
}

interface SecureMessage {
  message_id: string;
  sender_email: string;
  encrypted_message: string;
  message_iv: string;
  timestamp: string;
  session_id: string;
}

const SecureMessaging: React.FC<Props> = ({ showToast, onReAuthenticate, currentUserEmail }) => {
  const [recipientEmail, setRecipientEmail] = useState('');
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState<SecureMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decryptedMessages, setDecryptedMessages] = useState<{[key: string]: string}>({});
  const [sessionStatus, setSessionStatus] = useState<'valid' | 'expired' | 'checking'>('checking');
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [hoveredMessage, setHoveredMessage] = useState<string | null>(null);
  const [reEncrypting, setReEncrypting] = useState<string | null>(null);

  useEffect(() => {
    loadMessages();
    checkSessionStatus();
  }, []);

  const checkSessionStatus = async () => {
    try {
      const sharedSecret = await getValidSessionSecret();
      setSessionStatus(sharedSecret ? 'valid' : 'expired');
    } catch (error) {
      setSessionStatus('expired');
    }
  };

  const loadMessages = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await receiveSecureMessages();
      setMessages(response.messages);
    } catch (err: any) {
      setError(err.message || 'Failed to load messages');
      showToast?.(err.message || 'Failed to load messages', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!recipientEmail.trim() || !message.trim()) {
      setError('Please enter both recipient email and message');
      return;
    }

    setSending(true);
    try {
      // Check session status before sending
      const sharedSecret = await getValidSessionSecret();
      if (!sharedSecret) {
        setError('Session expired. Please re-authenticate to send messages.');
        showToast?.('Session expired. Please re-authenticate to decrypt messages.', 'error');
        return;
      }

      if (!currentUserEmail) {
        setError('User email not available. Please re-authenticate.');
        showToast?.('User email not available. Please re-authenticate.', 'error');
        return;
      }

      // Encrypt message with message-specific key
      const messageId = `msg-${Date.now()}`; // Generate a unique message ID
      const { ciphertext, iv } = await aesGcmEncryptWithMessageKey(
        message,
        currentUserEmail,
        recipientEmail.trim(),
        messageId
      );

      await sendSecureMessage(recipientEmail.trim(), ciphertext, iv, messageId);
      setMessage('');
      setRecipientEmail('');
      showToast?.('Secure message sent successfully!', 'success');
      loadMessages(); // Refresh message list
    } catch (err: any) {
      setError(err.message || 'Failed to send message');
      showToast?.(err.message || 'Failed to send message', 'error');
    } finally {
      setSending(false);
    }
  };

  const handleDecryptMessage = async (messageId: string, encryptedMessage: string, messageIv: string) => {
    try {
      // Check session status first
      const sharedSecret = await getValidSessionSecret();
      if (!sharedSecret) {
        showToast?.('Session expired. Please re-authenticate to decrypt messages.', 'error');
        return;
      }

      // Check if message exists
      const message = messages.find(m => m.message_id === messageId);
      if (!message) {
        showToast?.('Message not found.', 'error');
        return;
      }

      // Try to decrypt the message
      try {
        if (!currentUserEmail) {
          showToast?.('User email not available. Please re-authenticate.', 'error');
          return;
        }

        const decrypted = await aesGcmDecryptWithMessageKey(
          encryptedMessage,
          messageIv,
          message.sender_email,
          currentUserEmail,
          messageId
        );
        
        setDecryptedMessages(prev => ({
          ...prev,
          [messageId]: decrypted
        }));
        
        showToast?.('Message decrypted successfully!', 'success');
      } catch (decryptErr: any) {
        console.error('Decryption error:', decryptErr);
        
        // Check session status again
        const currentSharedSecret = await getValidSessionSecret();
        if (!currentSharedSecret) {
          showToast?.('Session expired. Please re-authenticate to decrypt messages.', 'error');
          return;
        }
        
        // Try to re-authenticate if session key is corrupted
        if (decryptErr.message.includes('session') || decryptErr.message.includes('key')) {
          showToast?.('Cannot decrypt message. The message may have been corrupted or the key derivation failed.', 'error');
        } else if (decryptErr.message.includes('authentication')) {
          showToast?.('Failed to decrypt message. The message may have been encrypted with a different session key.', 'error');
        } else if (decryptErr.message.includes('invalid')) {
          showToast?.('Invalid encryption key. Session may have changed.', 'error');
        } else {
          showToast?.('Failed to decrypt message: ' + decryptErr.message, 'error');
        }
      }
    } catch (err: any) {
      console.error('Decryption error:', err);
      showToast?.('Failed to decrypt message: ' + err.message, 'error');
    }
  };

  const handleDeleteMessage = async (messageId: string) => {
    try {
      await deleteSecureMessage(messageId);
      setMessages(prev => prev.filter(msg => msg.message_id !== messageId));
      setDecryptedMessages(prev => {
        const newState = { ...prev };
        delete newState[messageId];
        return newState;
      });
      setDeleteConfirm(null); // Clear the confirmation state
      showToast?.('Message deleted successfully', 'success');
    } catch (err: any) {
      setDeleteConfirm(null); // Clear the confirmation state even on error
      showToast?.('Failed to delete message: ' + err.message, 'error');
    }
  };

  const handleReEncryptMessage = async (messageId: string) => {
    // Check if message is decrypted first
    if (!decryptedMessages[messageId]) {
      showToast?.('Message must be decrypted first before re-encrypting', 'error');
      return;
    }

    setReEncrypting(messageId);
    try {
      // Find the original message
      const originalMessage = messages.find(msg => msg.message_id === messageId);
      if (!originalMessage) {
        showToast?.('Message not found', 'error');
        return;
      }

      // Get the decrypted content
      const decryptedContent = decryptedMessages[messageId];

        if (!currentUserEmail) {
          showToast?.('User email not available. Please re-authenticate.', 'error');
          return;
        }

        // Re-encrypt with new message-specific key
        const { ciphertext, iv } = await aesGcmEncryptWithMessageKey(
          decryptedContent,
          originalMessage.sender_email,
          currentUserEmail,
          messageId
        );

      // Update the message on the server
      await updateMessageEncryption(messageId, ciphertext, iv, messageId);

      // Update local state
      setMessages(prev => prev.map(msg => 
        msg.message_id === messageId 
          ? { ...msg, encrypted_message: ciphertext, message_iv: iv }
          : msg
      ));

      // Clear the decrypted content from the UI
      setDecryptedMessages(prev => {
        const newState = { ...prev };
        delete newState[messageId];
        return newState;
      });

      showToast?.('Message re-encrypted successfully', 'success');
    } catch (err: any) {
      showToast?.('Failed to re-encrypt message: ' + err.message, 'error');
    } finally {
      setReEncrypting(null);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="secure-messaging">
      <h3 style={{ margin: '10px 0 6px 0', fontWeight: 600 }}>Secure Messaging</h3>
      <p style={{ marginBottom: 16, opacity: 0.8, fontSize: '0.9em' }}>
        Send encrypted messages to other users. Messages are encrypted with message-specific keys derived from sender, recipient, and message ID, ensuring they can be decrypted regardless of session changes.
      </p>

      {/* Session Status Indicator */}
      <div style={{ 
        marginBottom: 16, 
        padding: '8px 12px', 
        borderRadius: 6, 
        background: sessionStatus === 'valid' ? '#1e3a2e' : sessionStatus === 'expired' ? '#3a1e1e' : '#2a2a2a',
        border: `1px solid ${sessionStatus === 'valid' ? '#28a745' : sessionStatus === 'expired' ? '#dc3545' : '#6c757d'}`,
        display: 'flex',
        alignItems: 'center',
        gap: 8
      }}>
        <span style={{ fontSize: '1.2em' }}>
          {sessionStatus === 'valid' ? '🔒' : sessionStatus === 'expired' ? '⚠️' : '⏳'}
        </span>
        <span style={{ fontSize: '0.9em', fontWeight: 500 }}>
          {sessionStatus === 'valid' ? 'Session Active' : 
           sessionStatus === 'expired' ? 'Session Expired - Re-authenticate Required' : 
           'Checking Session...'}
        </span>
        {sessionStatus === 'expired' && (
          <button
            onClick={onReAuthenticate}
            style={{
              background: '#dc3545',
              color: '#fff',
              border: 'none',
              borderRadius: 4,
              padding: '4px 8px',
              fontSize: '0.8em',
              cursor: 'pointer',
              marginLeft: 'auto'
            }}
          >
            Re-authenticate
          </button>
        )}
      </div>

      {/* Send Message Form */}
      <form onSubmit={handleSendMessage} style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label htmlFor="recipient-email" style={{ fontWeight: 500, marginBottom: 4, display: 'block' }}>
              Recipient Email:
            </label>
            <input
              id="recipient-email"
              type="email"
              value={recipientEmail}
              onChange={e => setRecipientEmail(e.target.value)}
              disabled={sending}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 6,
                border: '1px solid #3a506b',
                background: '#232b3e',
                color: '#e0e6f0',
                fontSize: '1em',
                height: '40px',
                boxSizing: 'border-box'
              }}
              placeholder="Enter recipient's email..."
            />
          </div>
          <button
            type="submit"
            disabled={sending || !recipientEmail.trim() || !message.trim()}
            style={{
              background: sending || !recipientEmail.trim() || !message.trim() ? '#3a506b' : '#2196f3',
              color: '#fff',
              border: 'none',
              borderRadius: 6,
              padding: '8px 12px',
              fontWeight: 600,
              fontSize: '1.2em',
              cursor: sending || !recipientEmail.trim() || !message.trim() ? 'not-allowed' : 'pointer',
              transition: 'background 0.2s',
              whiteSpace: 'nowrap',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              minWidth: '40px',
              height: '40px',
              boxSizing: 'border-box',
              alignSelf: 'flex-end',
              marginBottom: '4px'
            }}
            title={sending ? 'Sending...' : 'Send Message'}
          >
            {sending ? '⏳' : (
              <svg 
                width="16" 
                height="16" 
                viewBox="0 0 24 24" 
                fill="currentColor"
                style={{ transform: 'rotate(45deg)' }}
              >
                <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
              </svg>
            )}
          </button>
        </div>
        
        <div>
          <label htmlFor="message-content" style={{ fontWeight: 500, marginBottom: 4, display: 'block' }}>
            Message:
          </label>
          <textarea
            id="message-content"
            value={message}
            onChange={e => setMessage(e.target.value)}
            disabled={sending}
            rows={3}
            style={{
              width: '60%',
              maxWidth: '500px',
              padding: '8px 12px',
              borderRadius: 6,
              border: '1px solid #3a506b',
              background: '#232b3e',
              color: '#e0e6f0',
              fontSize: '1em',
              resize: 'vertical',
              fontFamily: 'inherit'
            }}
            placeholder="Type your secure message..."
          />
        </div>
      </form>

      {error && (
        <div className="alert alert-error" role="alert" aria-live="polite" style={{ marginBottom: 16 }}>
          <span aria-hidden="true">⚠️</span> {error}
        </div>
      )}

      {/* Received Messages */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h4 style={{ margin: 0, fontWeight: 600 }}>Received Messages</h4>
          <button
            onClick={loadMessages}
            disabled={loading}
            style={{
              background: '#3a506b',
              color: '#fff',
              border: 'none',
              borderRadius: 4,
              padding: '4px 8px',
              fontSize: '0.8em',
              cursor: loading ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        {messages.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 20, opacity: 0.6 }}>
            No messages received
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {messages.map(msg => (
              <div
                key={msg.message_id}
                data-message-id={msg.message_id}
                style={{
                  border: '1px solid #3a506b',
                  borderRadius: 8,
                  padding: 12,
                  background: '#1a2332',
                  position: 'relative',
                  transition: 'all 0.2s ease'
                }}
                onMouseEnter={() => setHoveredMessage(msg.message_id)}
                onMouseLeave={() => setHoveredMessage(null)}
              >
                {/* Re-encrypt hover overlay */}
                {hoveredMessage === msg.message_id && decryptedMessages[msg.message_id] && (
                  <div style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    background: 'rgba(0, 0, 0, 0.8)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    borderRadius: 8,
                    zIndex: 10
                  }}>
                    <button
                      onClick={() => handleReEncryptMessage(msg.message_id)}
                      disabled={reEncrypting === msg.message_id}
                      style={{
                        background: reEncrypting === msg.message_id ? '#3a506b' : '#17a2b8',
                        color: '#fff',
                        border: 'none',
                        borderRadius: 6,
                        padding: '8px 16px',
                        fontSize: '0.9em',
                        cursor: reEncrypting === msg.message_id ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6
                      }}
                    >
                      {reEncrypting === msg.message_id ? (
                        <>
                          <span>⏳</span>
                          Re-encrypting...
                        </>
                      ) : (
                        <>
                          <span>🔒</span>
                          Re-encrypt Message
                        </>
                      )}
                    </button>
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <div>
                    <strong style={{ color: '#e0e6f0' }}>From: {msg.sender_email}</strong>
                    <div style={{ fontSize: '0.8em', opacity: 0.7, marginTop: 2 }}>
                      {formatTimestamp(msg.timestamp)}
                    </div>
                  </div>
                  <button
                    onClick={() => setDeleteConfirm(msg.message_id)}
                    style={{
                      background: '#dc3545',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 4,
                      padding: '2px 6px',
                      fontSize: '0.7em',
                      cursor: 'pointer'
                    }}
                    title="Delete message"
                  >
                    ×
                  </button>
                </div>
                
                {decryptedMessages[msg.message_id] ? (
                  <div style={{
                    background: '#2a3441',
                    padding: 8,
                    borderRadius: 4,
                    marginTop: 8,
                    whiteSpace: 'pre-wrap'
                  }}>
                    {decryptedMessages[msg.message_id]}
                  </div>
                ) : (
                  <div style={{ marginTop: 8 }}>
                    <button
                      onClick={() => handleDecryptMessage(msg.message_id, msg.encrypted_message, msg.message_iv)}
                      style={{
                        background: '#28a745',
                        color: '#fff',
                        border: 'none',
                        borderRadius: 4,
                        padding: '4px 8px',
                        fontSize: '0.8em',
                        cursor: 'pointer'
                      }}
                    >
                      Decrypt Message
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Delete Confirmation Popup */}
      {deleteConfirm && (
        <div 
          key={`delete-modal-${deleteConfirm}`}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}
        >
          <div style={{
            background: '#1a2332',
            border: '1px solid #3a506b',
            borderRadius: 8,
            padding: 20,
            maxWidth: 400,
            width: '90%',
            textAlign: 'center'
          }}>
            <h4 style={{ margin: '0 0 16px 0', color: '#e0e6f0' }}>Confirm Delete</h4>
            <p style={{ margin: '0 0 20px 0', color: '#b0b8c4' }}>
              Are you sure you want to delete this message? This action cannot be undone.
            </p>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
              <button
                onClick={() => setDeleteConfirm(null)}
                style={{
                  background: '#3a506b',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 4,
                  padding: '8px 16px',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  handleDeleteMessage(deleteConfirm);
                  setDeleteConfirm(null); // Clear the confirmation state immediately
                }}
                style={{
                  background: '#dc3545',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 4,
                  padding: '8px 16px',
                  cursor: 'pointer'
                }}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecureMessaging;