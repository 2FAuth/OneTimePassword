//
//  KeychainTests.swift
//  OneTimePassword
//
//  Copyright (c) 2013-2018 Matt Rubin and the OneTimePassword authors
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

import XCTest
import OneTimePassword
import Base32

let testToken = Token(
    name: "Name",
    issuer: "Issuer",
    generator: Generator(
        factor: .timer(period: 45),
        secret: MF_Base32Codec.data(fromBase32String: "AAAQEAYEAUDAOCAJBIFQYDIOB4"),
        algorithm: .sha256,
        digits: 8
    )!
)

class KeychainTests: XCTestCase {
    let keychain = OTPKeychain()

    func testPersistentTokenWithIdentifier() {
        // Create a token
        let token = testToken

        // Save the token
        var persistentToken = PersistentToken(token: token, id: UUID().uuidString, ckData: nil)
        do {
            try keychain.add(persistentToken)
        } catch {
            XCTFail("addToken(_:) failed with error: \(error)")
            return
        }

        // Restore the token
        do {
            let fetchedToken = try keychain.persistentToken(with: persistentToken.id)
            XCTAssertEqual(fetchedToken, persistentToken, "Token should have been saved to keychain")
        } catch {
            XCTFail("persistentToken(with:) failed with error: \(error)")
        }

        // Modify the token
        let modifiedToken = Token(
            name: "New Name",
            issuer: "New Issuer",
            generator: token.generator.successor()
        )
        do {
            // provide ckData and save
            persistentToken.ckData = "123".data(using: .utf8)
            
            let updatedPersistentToken = PersistentToken(token: modifiedToken,
                                                         id: persistentToken.id,
                                                         ckData: persistentToken.ckData)
            try keychain.update(updatedPersistentToken)
            
            let fetchedToken = try keychain.persistentToken(with: persistentToken.id)!
            XCTAssertEqual(fetchedToken.id, updatedPersistentToken.id)
            XCTAssertEqual(fetchedToken.token, modifiedToken)
        } catch {
            XCTFail("updatePersistentToken(_:withToken:) failed with error: \(error)")
        }

        // Fetch the token again
        do {
            let fetchedToken = try keychain.persistentToken(with: persistentToken.id)
            XCTAssertEqual(fetchedToken?.token, modifiedToken)
            XCTAssertEqual(fetchedToken?.id, persistentToken.id)
        } catch {
            XCTFail("persistentToken(with:) failed with error: \(error)")
        }

        // Remove the token
        do {
            try keychain.delete(persistentToken)
        } catch {
            XCTFail("deletePersistentToken(_:) failed with error: \(error)")
        }

        // Attempt to restore the deleted token
        do {
            let fetchedToken = try keychain.persistentToken(with: persistentToken.id)
            XCTAssertNil(fetchedToken, "Token should have been removed from keychain")
        } catch {
            XCTFail("persistentToken(with:) failed with error: \(error)")
        }
    }

    // swiftlint:disable:next function_body_length
    func testDuplicateTokens() {
        let token1 = testToken, token2 = testToken

        // Add both tokens to the keychain
        let item1 = PersistentToken(token: token1, id: UUID().uuidString, ckData: nil)
        let item2 = PersistentToken(token: token2, id: UUID().uuidString, ckData: nil)
        do {
            try keychain.add(item1)
            try keychain.add(item2)
            
            let fetchedItem1 = try keychain.persistentToken(with: item1.id)!
            let fetchedItem2 = try keychain.persistentToken(with: item2.id)!
            XCTAssertNotEqual(fetchedItem1, fetchedItem2)
        } catch {
            XCTFail("addToken(_:) failed with error: \(error)")
            return
        }

        // Fetch both tokens from the keychain
        do {
            let fetchedItem1 = try keychain.persistentToken(with: item1.id)
            let fetchedItem2 = try keychain.persistentToken(with: item2.id)
            XCTAssertEqual(fetchedItem1, item1, "Saved token not found in keychain")
            XCTAssertEqual(fetchedItem2, item2, "Saved token not found in keychain")
        } catch {
            XCTFail("persistentToken(with:) failed with error: \(error)")
        }

        // Remove the first token from the keychain
        do {
            try keychain.delete(item1)
        } catch {
            XCTFail("deletePersistentToken(_:) failed with error: \(error)")
        }

        do {
            let checkItem1 = try keychain.persistentToken(with: item1.id)
            let checkItem2 = try keychain.persistentToken(with: item2.id)
            XCTAssertNil(checkItem1, "Token should not be in keychain: \(token1)")
            XCTAssertNotNil(checkItem2, "Token should be in keychain: \(token2)")
        } catch {
            XCTFail("persistentToken(with:) failed with error: \(error)")
        }

        // Remove the second token from the keychain
        do {
            try keychain.delete(item2)
        } catch {
            XCTFail("deletePersistentToken(_:) failed with error: \(error)")
        }

        do {
            let recheckItem1 = try keychain.persistentToken(with: item1.id)
            let recheckItem2 = try keychain.persistentToken(with: item2.id)
            XCTAssertNil(recheckItem1, "Token should not be in keychain: \(token1)")
            XCTAssertNil(recheckItem2, "Token should not be in keychain: \(token2)")
        } catch {
            XCTFail("persistentToken(with:) failed with error: \(error)")
        }

        // Try to remove both tokens from the keychain again
        XCTAssertNoThrow(try keychain.delete(item1), "Removing again should not fail: \(token1)")
        XCTAssertNoThrow(try keychain.delete(item2), "Removing again should not fail: \(token2)")
    }

    func testAllPersistentTokens() {
        let token1 = testToken, token2 = testToken, token3 = testToken

        do {
            let noTokens = try keychain.allPersistentTokens()
            XCTAssert(noTokens.isEmpty, "Expected no tokens in keychain: \(noTokens)")
        } catch {
            XCTFail("allPersistentTokens() failed with error: \(error)")
        }

        let persistentToken1 = PersistentToken(token: token1, id: UUID().uuidString, ckData: nil)
        let persistentToken2 = PersistentToken(token: token2, id: UUID().uuidString, ckData: nil)
        let persistentToken3 = PersistentToken(token: token3, id: UUID().uuidString, ckData: nil)
        do {
            try keychain.add(persistentToken1)
            try keychain.add(persistentToken2)
            try keychain.add(persistentToken3)
        } catch {
            XCTFail("addToken(_:) failed with error: \(error)")
            return
        }

        do {
            let allTokens = try keychain.allPersistentTokens()
            XCTAssertEqual(allTokens, [persistentToken1, persistentToken2, persistentToken3],
                           "Tokens not correctly recovered from keychain")
        } catch {
            XCTFail("allPersistentTokens() failed with error: \(error)")
        }

        do {
            try keychain.deleteAll()
        } catch {
            XCTFail("deletePersistentToken(_:) failed with error: \(error)")
        }

        do {
            let noTokens = try keychain.allPersistentTokens()
            XCTAssert(noTokens.isEmpty, "Expected no tokens in keychain: \(noTokens)")
        } catch {
            XCTFail("allPersistentTokens() failed with error: \(error)")
        }
    }

    func testMissingData() throws {
        let keychainAttributes: [String: AnyObject] = [
            kSecValueData as String:    testToken.generator.secret as NSData,
        ]

        let identifier = try addKeychainItem(with: keychainAttributes)

        XCTAssertThrowsError(try keychain.persistentToken(with: identifier))
        // TODO: Restore deserialization error handling in allPersistentTokens()
//        XCTAssertThrowsError(try keychain.allPersistentTokens())

        XCTAssertNoThrow(try deleteKeychainItem(for: identifier),
                         "Failed to delete the test token from the keychain. This may cause future test runs to fail.")
    }

    func testMissingSecret() throws {
        let data = try testToken.toURL().absoluteString.data(using: .utf8)!

        let keychainAttributes: [String: AnyObject] = [
            kSecAttrGeneric as String:  data as NSData,
        ]

        let identifier = try addKeychainItem(with: keychainAttributes)

        XCTAssertThrowsError(try keychain.persistentToken(with: identifier))
        // TODO: Restore deserialization error handling in allPersistentTokens()
//        XCTAssertThrowsError(try keychain.allPersistentTokens())

        XCTAssertNoThrow(try deleteKeychainItem(for: identifier),
                         "Failed to delete the test token from the keychain. This may cause future test runs to fail.")
    }

    func testBadData() throws {
        let badData = " ".data(using: .utf8)!

        let keychainAttributes: [String: AnyObject] = [
            kSecAttrGeneric as String:  badData as NSData,
            kSecValueData as String:    testToken.generator.secret as NSData,
        ]

        let identifier = try addKeychainItem(with: keychainAttributes)

        XCTAssertThrowsError(try keychain.persistentToken(with: identifier))
        // TODO: Restore deserialization error handling in allPersistentTokens()
//        XCTAssertThrowsError(try keychain.allPersistentTokens())

        XCTAssertNoThrow(try deleteKeychainItem(for: identifier),
                         "Failed to delete the test token from the keychain. This may cause future test runs to fail.")
    }

    func testBadURL() throws {
        let badData = "http://example.com".data(using: .utf8)!

        let keychainAttributes: [String: AnyObject] = [
            kSecAttrGeneric as String:  badData as NSData,
            kSecValueData as String:    testToken.generator.secret as NSData,
        ]

        let identifier = try addKeychainItem(with: keychainAttributes)

        XCTAssertThrowsError(try keychain.persistentToken(with: identifier))
        // TODO: Restore deserialization error handling in allPersistentTokens()
//        XCTAssertThrowsError(try keychain.allPersistentTokens())

        XCTAssertNoThrow(try deleteKeychainItem(for: identifier),
                         "Failed to delete the test token from the keychain. This may cause future test runs to fail.")
    }
}

// MARK: OTPKeychain helpers

private func addKeychainItem(with attributes: [String: AnyObject]) throws -> String {
    var mutableAttributes = attributes
    mutableAttributes[kSecClass as String] = kSecClassGenericPassword
    mutableAttributes[kSecAttrService as String] = "app.2fauth.token" as NSString

    // Set a random string for the account name.
    // We never query by or display this value, but the keychain requires it to be unique.
    let identifier = UUID().uuidString
    if mutableAttributes[kSecAttrAccount as String] == nil {
        mutableAttributes[kSecAttrAccount as String] = identifier as NSString
    }

    var result: AnyObject?
    let resultCode: OSStatus = withUnsafeMutablePointer(to: &result) {
        SecItemAdd(mutableAttributes as CFDictionary, $0)
    }

    guard resultCode == errSecSuccess else {
        throw KeychainWrapper.Error.systemError(resultCode)
    }
    return identifier
}

public func deleteKeychainItem(for identifier: String) throws {
    let queryDict: [String: AnyObject] = [
        kSecClass as String:               kSecClassGenericPassword,
        kSecAttrAccount as String:         identifier as NSString,
        kSecAttrService as String:         "app.2fauth.token" as NSString,
    ]

    let resultCode = SecItemDelete(queryDict as CFDictionary)

    guard resultCode == errSecSuccess else {
        throw KeychainWrapper.Error.systemError(resultCode)
    }
}
