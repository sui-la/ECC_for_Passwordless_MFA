import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders ECC Passwordless MFA title', () => {
  render(<App />);
  const titleElement = screen.getByText(/ECC Passwordless Multi-Factor Authentication/i);
  expect(titleElement).toBeInTheDocument();
});

test('renders registration section', () => {
  render(<App />);
  const registerElement = screen.getByRole('heading', { name: /Register/i });
  expect(registerElement).toBeInTheDocument();
});

test('renders authentication section', () => {
  render(<App />);
  const authElement = screen.getByRole('heading', { name: /Authenticate/i });
  expect(authElement).toBeInTheDocument();
});
