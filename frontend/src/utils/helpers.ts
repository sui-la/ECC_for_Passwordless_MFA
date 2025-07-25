// General helper functions for the frontend

// Toast notification function
export const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
  // Create a simple toast notification
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    border-radius: 8px;
    color: white;
    font-weight: 500;
    z-index: 10000;
    animation: slideIn 0.3s ease-out;
    max-width: 300px;
    word-wrap: break-word;
  `;

  // Set background color based on type
  switch (type) {
    case 'success':
      toast.style.backgroundColor = '#10b981';
      break;
    case 'error':
      toast.style.backgroundColor = '#ef4444';
      break;
    case 'info':
    default:
      toast.style.backgroundColor = '#3b82f6';
      break;
  }

  // Add CSS animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }
  `;
  document.head.appendChild(style);

  document.body.appendChild(toast);

  // Remove toast after 3 seconds
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease-in';
    toast.style.animationFillMode = 'forwards';
    
    // Add slideOut animation
    const slideOutStyle = document.createElement('style');
    slideOutStyle.textContent = `
      @keyframes slideOut {
        from {
          transform: translateX(0);
          opacity: 1;
        }
        to {
          transform: translateX(100%);
          opacity: 0;
        }
      }
    `;
    document.head.appendChild(slideOutStyle);
    
    setTimeout(() => {
      document.body.removeChild(toast);
    }, 300);
  }, 3000);
};