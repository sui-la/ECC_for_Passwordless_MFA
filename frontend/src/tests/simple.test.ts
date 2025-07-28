describe('Simple Test', () => {
  it('should work', () => {
    expect(1 + 1).toBe(2);
  });

  it('should have TextEncoder', () => {
    expect(global.TextEncoder).toBeDefined();
  });

  it('should have crypto', () => {
    expect(global.crypto).toBeDefined();
  });
}); 