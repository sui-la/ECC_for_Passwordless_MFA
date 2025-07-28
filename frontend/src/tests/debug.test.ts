import '@testing-library/jest-dom';

describe('Test Setup Debug', () => {
  it('should have TextEncoder available', () => {
    expect(global.TextEncoder).toBeDefined();
    expect(new TextEncoder()).toBeInstanceOf(TextEncoder);
  });

  it('should have TextDecoder available', () => {
    expect(global.TextDecoder).toBeDefined();
    expect(new TextDecoder()).toBeInstanceOf(TextDecoder);
  });

  it('should have crypto available', () => {
    expect(global.crypto).toBeDefined();
    expect(global.crypto.subtle).toBeDefined();
  });

  it('should have atob and btoa available', () => {
    expect(global.atob).toBeDefined();
    expect(global.btoa).toBeDefined();
  });

  it('should encode and decode text correctly', () => {
    const text = 'Hello, World!';
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    
    const encoded = encoder.encode(text);
    const decoded = decoder.decode(encoded);
    
    expect(decoded).toBe(text);
  });
}); 