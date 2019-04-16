//
//  Cryptor.h
//  EncryptionDemo
//
//  Created by zhouqiang on 2019/3/26.
//  Copyright © 2019 test. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

typedef size_t CCKeySize;

CCCryptorStatus CCCryptAdvanced(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,
                                const void *key, CCKeySize keyLength, const void *iv,
                                const void *dataIn, size_t dataInLength,
                                void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);

NSData * _Nullable CCCryptDataAdvanced(CCOperation op,
                                       CCMode mode,
                                       CCAlgorithm alg,
                                       CCPadding padding,
                                       CCKeySize keySize,
                                       NSData *dataIn,
                                       NSData *key,
                                       NSData * _Nullable iv);

NSString * _Nullable CCCryptStringAdvanced(CCOperation op,
                                           CCMode mode,
                                           CCAlgorithm alg,
                                           CCPadding padding,
                                           CCKeySize keySize,
                                           NSString *sourceIn,
                                           NSString *keyString,
                                           NSString * _Nullable ivString);

NS_ASSUME_NONNULL_END
