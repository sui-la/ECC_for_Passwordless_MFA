describe('Basic Test Setup', () => {
  it('should have basic functionality', () => {
    expect(1 + 1).toBe(2);
  });

  it('should have TextEncoder', () => {
    expect(global.TextEncoder).toBeDefined();
    const encoder = new TextEncoder();
    expect(encoder.encode('test')).toBeInstanceOf(Uint8Array);
  });

  it('should have TextDecoder', () => {
    expect(global.TextDecoder).toBeDefined();
    const decoder = new TextDecoder();
    expect(decoder.decode(new Uint8Array([116, 101, 115, 116]))).toBe('test');
  });

  it('should have atob and btoa', () => {
    expect(global.atob).toBeDefined();
    expect(global.btoa).toBeDefined();
    expect(global.btoa('test')).toBe('dGVzdA==');
    expect(global.atob('dGVzdA==')).toBe('test');
  });
});

// Make this file a module
export {}; 