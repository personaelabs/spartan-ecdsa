/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    "^.+\\.(ts|js)$$": ["ts-jest", { tsconfig: "<rootDir>/tsconfig.tests.json" }]
  },
  moduleNameMapper: {
    "@src/(.*)$": "<rootDir>/src/$1",
  },
  testTimeout: 600000,
};