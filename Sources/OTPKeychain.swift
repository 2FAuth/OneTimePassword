//
//  OTPKeychain.swift
//  OneTimePassword
//
//  Copyright (c) 2014-2018 Matt Rubin and the OneTimePassword authors
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

import Foundation

/// The `OTPKeychain`'s shared instance is a singleton which represents the iOS system keychain used
/// to securely store tokens.
public final class OTPKeychain {
    private let keychain: KeychainWrapper
    
    public init() {
        keychain = KeychainWrapper(service: "app.2fauth.token")
    }

    // MARK: Read

    /// Finds the persistent token with the given identifer, if one exists.
    ///
    /// - parameter id: The persistent id for the desired token.
    ///
    /// - throws: A `OTPKeychain.Error` if an error occurred.
    /// - returns: The persistent token, or `nil` if no token matched the given id.
    public func persistentToken(with identifier: String) throws -> PersistentToken? {
        try keychain.item(with: identifier).map(PersistentToken.init(keychainDictionary:))
    }

    /// Returns the set of all persistent tokens found in the keychain.
    ///
    /// - throws: A `OTPKeychain.Error` if an error occurred.
    public func allPersistentTokens() throws -> Set<PersistentToken> {
        let allItems = try keychain.allItems()
        // This code intentionally ignores items which fail deserialization, instead opting to return as many readable
        // tokens as possible.
        // TODO: Restore deserialization error handling, in a way that provides info on the failure reason and allows
        //       the caller to choose whether to fail completely or recover some data.
        return Set(allItems.compactMap({ try? PersistentToken(keychainDictionary: $0) }))
    }

    // MARK: Write

    /// Adds the given token to the keychain and returns the persistent token which contains it.
    ///
    /// - parameter token: The token to save to the keychain.
    ///
    /// - throws: A `OTPKeychain.Error` if the token was not added successfully.
    /// - returns: The new persistent token.
    public func add(_ token: Token) throws -> PersistentToken {
        let identifier = UUID().uuidString
        let attributes = try serialize(token: token)
        try keychain.addItem(with: identifier, attributes: attributes)
        return PersistentToken(token: token, identifier: identifier, ckData: nil)
    }

    /// Updates the given persistent token with a new token value.
    ///
    /// - parameter persistentToken: The persistent token to update.
    /// - parameter token: The new token value.
    ///
    /// - throws: A `OTPKeychain.Error` if the update did not succeed.
    /// - returns: The updated persistent token.
    public func update(_ persistentToken: PersistentToken, with token: Token) throws -> PersistentToken {
        let ckData = persistentToken.ckData
        let attributes = try serialize(token: token, ckData: ckData)
        try keychain.updateItem(with: persistentToken.id, attributes: attributes)
        return PersistentToken(token: token, identifier: persistentToken.id, ckData: ckData)
    }

    /// Deletes the given persistent token from the keychain.
    ///
    /// - note: After calling `deletePersistentToken(_:)`, the persistent token's `id` is no
    ///         longer valid, and the token should be discarded.
    ///
    /// - parameter persistentToken: The persistent token to delete.
    ///
    /// - throws: A `OTPKeychain.Error` if the deletion did not succeed.
    public func delete(_ persistentToken: PersistentToken) throws {
        try keychain.deleteItem(with: persistentToken.id)
    }
    
    // MARK: Private
    
    private func serialize(token: Token, ckData: Data? = nil) throws -> [String: AnyObject] {
        do {
            let url = try token.toURL()
            let tokenData = TokenData(url: url, ckData: ckData)
            let encodedData = try JSONEncoder().encode(tokenData)
            return [
                kSecAttrGeneric as String:  encodedData as NSData,
                kSecValueData as String:    token.generator.secret as NSData,
            ]
        }
        catch {
            throw Error.tokenSerializationFailure
        }
    }

    // MARK: Errors

    /// An error type enum representing the various errors a `OTPKeychain` operation can throw.
    public enum Error: Swift.Error {
        /// The given token could not be serialized to keychain data.
        case tokenSerializationFailure
    }
}

// MARK: - Private

private struct TokenData: Codable {
    let url: URL
    let ckData: Data?
}

private extension PersistentToken {
    enum DeserializationError: Error {
        case missingData
        case missingSecret
        case missingIdentifier
        case unreadableData
    }

    init(keychainDictionary: NSDictionary) throws {
        guard let tokenDataDecoded = keychainDictionary[kSecAttrGeneric as String] as? Data else {
            throw DeserializationError.missingData
        }
        guard let secret = keychainDictionary[kSecValueData as String] as? Data else {
            throw DeserializationError.missingSecret
        }
        guard let identifier = keychainDictionary[kSecAttrAccount as String] as? String else {
            throw DeserializationError.missingIdentifier
        }
        let url: URL
        let ckData: Data?
        do {
            let tokenData = try JSONDecoder().decode(TokenData.self, from: tokenDataDecoded)
            url = tokenData.url
            ckData = tokenData.ckData
        } catch {
            throw DeserializationError.unreadableData
        }
        let token = try Token(_url: url, secret: secret)
        self.init(token: token, identifier: identifier, ckData: ckData)
    }
}
