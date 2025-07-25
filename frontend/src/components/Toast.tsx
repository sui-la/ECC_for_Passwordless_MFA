import React, { useEffect, useState } from 'react';

interface ToastProps {
  message: string;
  type: 'success' | 'error' | 'info';
  onClose: () => void;
  className?: string;
}

const Toast: React.FC<ToastProps> = ({ message, type, onClose, className }) => {
  const [progress, setProgress] = useState(100);
  const [isExiting, setIsExiting] = useState(false);

  useEffect(() => {
    const duration = 3500; // 3.5 seconds
    const interval = 50; // Update every 50ms
    const steps = duration / interval;
    const decrement = 100 / steps;

    const progressTimer = setInterval(() => {
      setProgress(prev => {
        if (prev <= 0) {
          clearInterval(progressTimer);
          return 0;
        }
        return prev - decrement;
      });
    }, interval);

    const closeTimer = setTimeout(() => {
      setIsExiting(true);
      setTimeout(onClose, 300); // Wait for exit animation
    }, duration);

    return () => {
      clearInterval(progressTimer);
      clearTimeout(closeTimer);
    };
  }, [onClose]);

  const handleClose = () => {
    setIsExiting(true);
    setTimeout(onClose, 300);
  };

  const getIcon = () => {
    switch (type) {
      case 'success':
        return '✓';
      case 'error':
        return '✕';
      case 'info':
        return 'ℹ';
      default:
        return '•';
    }
  };

  const getAriaLabel = () => {
    switch (type) {
      case 'success':
        return 'Success notification';
      case 'error':
        return 'Error notification';
      case 'info':
        return 'Information notification';
      default:
        return 'Notification';
    }
  };

  return (
    <div 
      className={`toast toast-${type} ${isExiting ? 'toast-exit' : ''} ${className || ''}`}
      role="alert"
      aria-live="polite"
      aria-label={getAriaLabel()}
    >
      <div className="toast-content">
        <div className="toast-icon" aria-hidden="true">
          {getIcon()}
        </div>
        <div className="toast-message">
          {message}
        </div>
        <button 
          className="toast-close"
          onClick={handleClose}
          aria-label="Close notification"
          type="button"
        >
          <span aria-hidden="true">×</span>
        </button>
      </div>
      <div className="toast-progress">
        <div 
          className="toast-progress-bar"
          style={{ width: `${progress}%` }}
          aria-hidden="true"
        />
      </div>
    </div>
  );
};

export default Toast; 