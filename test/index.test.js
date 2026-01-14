import { expect } from 'chai'
import { split, combine } from '../src/index.js'

// Test mnemonics (these are well-known test vectors, NOT for production use)
const TEST_MNEMONIC_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const TEST_MNEMONIC_24 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'

describe('wdk-util-shamir-secret-sharing', () => {
  describe('split()', () => {
    it('should split a 12-word mnemonic into the specified number of shares', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 5, threshold: 3 })

      expect(shares).to.be.an('array')
      expect(shares).to.have.lengthOf(5)
      shares.forEach((share) => {
        expect(share).to.be.a('string')
        expect(share).to.match(/^[0-9a-f]+$/i)
      })
    })

    it('should split a 24-word mnemonic into shares', async () => {
      const shares = await split(TEST_MNEMONIC_24, { shares: 3, threshold: 2 })

      expect(shares).to.be.an('array')
      expect(shares).to.have.lengthOf(3)
    })

    it('should normalize whitespace in mnemonic', async () => {
      const mnemonicWithExtraSpaces =
        '  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon   about  '
      const shares = await split(mnemonicWithExtraSpaces, {
        shares: 3,
        threshold: 2,
      })

      expect(shares).to.be.an('array')
      expect(shares).to.have.lengthOf(3)
    })

    it('should throw error for empty mnemonic', async () => {
      try {
        await split('', { shares: 3, threshold: 2 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('Mnemonic cannot be empty')
      }
    })

    it('should throw error for invalid mnemonic word count', async () => {
      try {
        await split('abandon abandon abandon', { shares: 3, threshold: 2 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.include('Invalid mnemonic word count')
      }
    })

    it('should throw error for non-string mnemonic', async () => {
      try {
        await split(12345, { shares: 3, threshold: 2 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('Mnemonic must be a string')
      }
    })

    it('should throw error when shares is less than 2', async () => {
      try {
        await split(TEST_MNEMONIC_12, { shares: 1, threshold: 1 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('shares must be at least 2')
      }
    })

    it('should throw error when threshold is less than 2', async () => {
      try {
        await split(TEST_MNEMONIC_12, { shares: 3, threshold: 1 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('threshold must be at least 2')
      }
    })

    it('should throw error when threshold is greater than shares', async () => {
      try {
        await split(TEST_MNEMONIC_12, { shares: 3, threshold: 5 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal(
          'threshold cannot be greater than shares',
        )
      }
    })

    it('should throw error when shares exceeds 255', async () => {
      try {
        await split(TEST_MNEMONIC_12, { shares: 256, threshold: 2 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('shares cannot exceed 255')
      }
    })

    it('should throw error for missing options', async () => {
      try {
        await split(TEST_MNEMONIC_12)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.include('Options must be an object')
      }
    })

    it('should throw error for non-integer shares', async () => {
      try {
        await split(TEST_MNEMONIC_12, { shares: 3.5, threshold: 2 })
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('shares must be an integer')
      }
    })
  })

  describe('combine()', () => {
    it('should reconstruct mnemonic from all shares', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 5, threshold: 3 })
      const reconstructed = await combine(shares)

      expect(reconstructed).to.equal(TEST_MNEMONIC_12)
    })

    it('should reconstruct mnemonic from threshold number of shares', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 5, threshold: 3 })
      const reconstructed = await combine(shares.slice(0, 3))

      expect(reconstructed).to.equal(TEST_MNEMONIC_12)
    })

    it('should reconstruct mnemonic from any subset of threshold shares', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 5, threshold: 3 })

      // Try different combinations of 3 shares
      const combo1 = await combine([shares[0], shares[2], shares[4]])
      const combo2 = await combine([shares[1], shares[3], shares[4]])

      expect(combo1).to.equal(TEST_MNEMONIC_12)
      expect(combo2).to.equal(TEST_MNEMONIC_12)
    })

    it('should reconstruct 24-word mnemonic', async () => {
      const shares = await split(TEST_MNEMONIC_24, { shares: 3, threshold: 2 })
      const reconstructed = await combine(shares)

      expect(reconstructed).to.equal(TEST_MNEMONIC_24)
    })

    it('should throw error for non-array shares', async () => {
      try {
        await combine('not-an-array')
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal('Shares must be an array')
      }
    })

    it('should throw error for less than 2 shares', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 5, threshold: 3 })

      try {
        await combine([shares[0]])
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.equal(
          'At least 2 shares are required to reconstruct the secret',
        )
      }
    })

    it('should throw error for non-string share', async () => {
      try {
        await combine(['abc123', 12345, 'def456'])
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.include('must be a string')
      }
    })

    it('should throw error for invalid hex share', async () => {
      try {
        await combine(['abc123', 'xyz789', 'def456'])
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error.message).to.include('not a valid hex string')
      }
    })
  })

  describe('round-trip tests', () => {
    it('should work with 2-of-2 scheme', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 2, threshold: 2 })
      const reconstructed = await combine(shares)

      expect(reconstructed).to.equal(TEST_MNEMONIC_12)
    })

    it('should work with 3-of-5 scheme', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 5, threshold: 3 })
      const reconstructed = await combine(shares.slice(1, 4))

      expect(reconstructed).to.equal(TEST_MNEMONIC_12)
    })

    it('should work with 5-of-10 scheme', async () => {
      const shares = await split(TEST_MNEMONIC_12, { shares: 10, threshold: 5 })
      const reconstructed = await combine([
        shares[0],
        shares[2],
        shares[4],
        shares[6],
        shares[8],
      ])

      expect(reconstructed).to.equal(TEST_MNEMONIC_12)
    })

    it('should preserve exact mnemonic content through split and combine', async () => {
      const originalMnemonic =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

      for (let i = 0; i < 3; i++) {
        const shares = await split(originalMnemonic, {
          shares: 5,
          threshold: 3,
        })
        const reconstructed = await combine(shares.slice(0, 3))
        expect(reconstructed).to.equal(originalMnemonic)
      }
    })

    it('should work with 15-word mnemonic', async () => {
      const mnemonic15 =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address'
      const shares = await split(mnemonic15, { shares: 3, threshold: 2 })
      const reconstructed = await combine(shares)

      expect(reconstructed).to.equal(mnemonic15)
    })

    it('should work with 18-word mnemonic', async () => {
      const mnemonic18 =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent'
      const shares = await split(mnemonic18, { shares: 4, threshold: 3 })
      const reconstructed = await combine(shares)

      expect(reconstructed).to.equal(mnemonic18)
    })

    it('should work with 21-word mnemonic', async () => {
      const mnemonic21 =
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit'
      const shares = await split(mnemonic21, { shares: 5, threshold: 3 })
      const reconstructed = await combine(shares)

      expect(reconstructed).to.equal(mnemonic21)
    })
  })
})
