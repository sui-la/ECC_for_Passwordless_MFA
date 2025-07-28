export interface DeviceInfo {
  deviceType: 'mobile' | 'tablet' | 'desktop';
  os: string;
  browser: string;
  screenSize: string;
  userAgent: string;
}

export function detectDeviceInfo(): DeviceInfo {
  const userAgent = navigator.userAgent;
  const platform = navigator.platform;
  const screenWidth = window.screen.width;
  const screenHeight = window.screen.height;

  // Detect device type
  let deviceType: 'mobile' | 'tablet' | 'desktop' = 'desktop';
  if (/Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent)) {
    deviceType = screenWidth > 768 ? 'tablet' : 'mobile';
  }

  // Detect OS
  let os = 'Unknown';
  if (/Windows/i.test(userAgent)) {
    os = 'Windows';
  } else if (/Mac/i.test(userAgent)) {
    os = 'macOS';
  } else if (/iPhone|iPad|iPod/i.test(userAgent)) {
    os = 'iOS';
  } else if (/Android/i.test(userAgent)) {
    os = 'Android';
  } else if (/Linux/i.test(userAgent)) {
    os = 'Linux';
  }

  // Detect browser
  let browser = 'Unknown';
  if (/Chrome/i.test(userAgent) && !/Edge/i.test(userAgent)) {
    browser = 'Chrome';
  } else if (/Safari/i.test(userAgent) && !/Chrome/i.test(userAgent)) {
    browser = 'Safari';
  } else if (/Firefox/i.test(userAgent)) {
    browser = 'Firefox';
  } else if (/Edge/i.test(userAgent)) {
    browser = 'Edge';
  } else if (/Opera/i.test(userAgent)) {
    browser = 'Opera';
  }

  // Detect screen size
  let screenSize = 'Unknown';
  if (screenWidth < 768) {
    screenSize = 'Small';
  } else if (screenWidth < 1024) {
    screenSize = 'Medium';
  } else {
    screenSize = 'Large';
  }

  return {
    deviceType,
    os,
    browser,
    screenSize,
    userAgent
  };
}

export function generateDeviceName(deviceInfo: DeviceInfo): string {
  const { deviceType, os, browser } = deviceInfo;
  
  // Generate user-friendly device names
  switch (deviceType) {
    case 'mobile':
      if (os === 'iOS') {
        return `iPhone (${browser})`;
      } else if (os === 'Android') {
        return `Android Phone (${browser})`;
      } else {
        return `${os} Mobile (${browser})`;
      }
    
    case 'tablet':
      if (os === 'iOS') {
        return `iPad (${browser})`;
      } else if (os === 'Android') {
        return `Android Tablet (${browser})`;
      } else {
        return `${os} Tablet (${browser})`;
      }
    
    case 'desktop':
      if (os === 'macOS') {
        return `Mac (${browser})`;
      } else if (os === 'Windows') {
        return `Windows PC (${browser})`;
      } else if (os === 'Linux') {
        return `Linux PC (${browser})`;
      } else {
        return `${os} Desktop (${browser})`;
      }
    
    default:
      return `${os} (${browser})`;
  }
}

export function getDetailedDeviceInfo(): string {
  const deviceInfo = detectDeviceInfo();
  return `${deviceInfo.browser} on ${deviceInfo.os} ${deviceInfo.deviceType} (${deviceInfo.screenSize} screen)`;
}

export function getDeviceFingerprint(): string {
  const deviceInfo = detectDeviceInfo();
  const screenRes = `${window.screen.width}x${window.screen.height}`;
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const language = navigator.language;
  
  return `${deviceInfo.os}-${deviceInfo.browser}-${deviceInfo.deviceType}-${screenRes}-${timezone}-${language}`;
} 