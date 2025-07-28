import '@testing-library/jest-dom';

// Mock TextEncoder and TextDecoder
class MockTextEncoder {
  encode(input: string): Uint8Array {
    const buffer = Buffer.from(input, 'utf8');
    return new Uint8Array(buffer);
  }
}

class MockTextDecoder {
  decode(input: Uint8Array): string {
    return Buffer.from(input).toString('utf8');
  }
}

// Mock atob and btoa
const mockAtob = (str: string): string => {
  return Buffer.from(str, 'base64').toString('binary');
};

const mockBtoa = (str: string): string => {
  return Buffer.from(str, 'binary').toString('base64');
};

// Mock Web Crypto API
const mockCryptoSubtle = {
  generateKey: jest.fn(),
  exportKey: jest.fn(),
  importKey: jest.fn(),
  sign: jest.fn(),
  verify: jest.fn(),
  deriveBits: jest.fn(),
  deriveKey: jest.fn(),
  encrypt: jest.fn(),
  decrypt: jest.fn(),
  digest: jest.fn(),
};

const mockCrypto = {
  subtle: mockCryptoSubtle,
  getRandomValues: jest.fn(),
};

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
};

// Mock IndexedDB
const indexedDBMock = {
  open: jest.fn(),
};

// Mock fetch
global.fetch = jest.fn();

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Set up all global mocks
Object.defineProperty(global, 'TextEncoder', {
  value: MockTextEncoder,
  writable: true,
  configurable: true,
});

Object.defineProperty(global, 'TextDecoder', {
  value: MockTextDecoder,
  writable: true,
  configurable: true,
});

Object.defineProperty(global, 'atob', {
  value: mockAtob,
  writable: true,
  configurable: true,
});

Object.defineProperty(global, 'btoa', {
  value: mockBtoa,
  writable: true,
  configurable: true,
});

Object.defineProperty(global, 'crypto', {
  value: mockCrypto,
  writable: true,
  configurable: true,
});

Object.defineProperty(global, 'localStorage', {
  value: localStorageMock,
  writable: true,
  configurable: true,
});

Object.defineProperty(global, 'indexedDB', {
  value: indexedDBMock,
  writable: true,
  configurable: true,
});

// Set up window mocks
Object.defineProperty(window, 'crypto', {
  value: mockCrypto,
  writable: true,
  configurable: true,
});

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
  writable: true,
  configurable: true,
});

Object.defineProperty(window, 'indexedDB', {
  value: indexedDBMock,
  writable: true,
  configurable: true,
});

// Export mocks for use in tests
export { mockCrypto, mockCryptoSubtle, localStorageMock, indexedDBMock }; 