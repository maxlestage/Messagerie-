/** Tests unitaires « purs » (crypto) en Node, sans dépendances natives. */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
};
