//
//  KeychainWrapper.swift
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

public struct KeychainWrapper {
    /// An error type enum representing the various errors a `KeychainWrapper` operation can throw.
    public enum Error: LocalizedError {
        /// The keychain operation returned a system error code.
        case systemError(OSStatus)
        /// The keychain operation returned an unexpected type of data.
        case incorrectReturnType
        
        public var errorDescription: String? {
            switch self {
            case let .systemError(status):
                if #available(iOS 11.3, watchOS 4.3, tvOS 11.3, *) {
                    if let errorString = SecCopyErrorMessageString(status, nil) as NSString? {
                        return errorString as String
                    } else {
                        let nsError = NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
                        return nsError.localizedDescription
                    }
                } else {
                    let nsError = NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
                    return nsError.localizedDescription
                }
            case .incorrectReturnType:
                return NSLocalizedString("The keychain operation returned an unexpected type of data.", comment: "")
            }
        }
    }
    
    private let service: String
    
    public init(service: String) {
        self.service = service
    }
    
    func addOrUpdateItem(with identifier: String, attributes: [String: AnyObject]) throws {
        do {
            try addItem(with: identifier, attributes: attributes)
        } catch Error.systemError(let status) where status == errSecDuplicateItem {
            try updateItem(with: identifier, attributes: attributes)
        } catch {
            throw error
        }
    }
    
    func addItem(with identifier: String, attributes: [String: AnyObject]) throws {
        var mutableAttributes = attributes
        mutableAttributes[kSecClass as String] = kSecClassGenericPassword
        mutableAttributes[kSecAttrAccount as String] = identifier as NSString
        mutableAttributes[kSecAttrService as String] = service as NSString
        
        let resultCode = SecItemAdd(mutableAttributes as CFDictionary, nil)
        
        guard resultCode == errSecSuccess else {
            throw KeychainWrapper.Error.systemError(resultCode)
        }
    }
    
    func updateItem(with identifier: String, attributes: [String: AnyObject]) throws {
        let query: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: identifier as NSString,
            kSecAttrService as String: service as NSString,
        ]
        
        let resultCode = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        
        guard resultCode == errSecSuccess else {
            throw Error.systemError(resultCode)
        }
    }
    
    func deleteItem(with identifier: String) throws {
        let query: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: identifier as NSString,
            kSecAttrService as String: service as NSString,
        ]
        
        let resultCode = SecItemDelete(query as CFDictionary)
        
        guard resultCode == errSecSuccess || resultCode == errSecItemNotFound else {
            throw Error.systemError(resultCode)
        }
    }
    
    func item(with identifier: String) throws -> NSDictionary? {
        let query: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: identifier as NSString,
            kSecReturnAttributes as String: kCFBooleanTrue,
            kSecReturnData as String: kCFBooleanTrue,
            kSecAttrService as String: service as NSString,
        ]
        
        var result: AnyObject?
        let resultCode = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(query as CFDictionary, $0)
        }
        
        if resultCode == errSecItemNotFound {
            // Not finding any keychain items is not an error in this case. Return nil.
            return nil
        }
        guard resultCode == errSecSuccess else {
            throw Error.systemError(resultCode)
        }
        guard let keychainItem = result as? NSDictionary else {
            throw Error.incorrectReturnType
        }
        
        return keychainItem
    }
    
    func allItems() throws -> [NSDictionary] {
        let query: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: kCFBooleanTrue,
            kSecReturnData as String: kCFBooleanTrue,
            kSecAttrService as String: service as NSString,
        ]
        
        var result: AnyObject?
        let resultCode = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(query as CFDictionary, $0)
        }
        
        if resultCode == errSecItemNotFound {
            // Not finding any keychain items is not an error in this case. Return an empty array.
            return []
        }
        guard resultCode == errSecSuccess else {
            throw Error.systemError(resultCode)
        }
        guard let keychainItems = result as? [NSDictionary] else {
            throw Error.incorrectReturnType
        }
        
        return keychainItems
    }
}
