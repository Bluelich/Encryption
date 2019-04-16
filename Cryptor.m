//
//  Cryptor.m
//  EncryptionDemo
//
//  Created by zhouqiang on 2019/3/26.
//  Copyright © 2019 test. All rights reserved.
//

#import "Cryptor.h"

CCCryptorStatus CCCryptAdvanced(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,
                                const void *key, CCKeySize keyLength, const void *iv,
                                const void *dataIn, size_t dataInLength,
                                void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus retval = CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength, NULL, 0, 0, 0, &cryptor);
    if(kCCSuccess != retval) return retval;
    size_t needed = CCCryptorGetOutputLength(cryptor, dataInLength, true);
    if(dataOutMoved != NULL) *dataOutMoved = needed;
    if(needed > dataOutAvailable) { retval = kCCBufferTooSmall; goto out; }
    size_t updateLen = 0, finalLen = 0;
    retval = CCCryptorUpdate(cryptor, dataIn, dataInLength, dataOut, dataOutAvailable, &updateLen);
    if(kCCSuccess != retval) goto out;
    dataOut += updateLen; dataOutAvailable -= updateLen;
    retval = CCCryptorFinal(cryptor, dataOut, dataOutAvailable, &finalLen);
    if(dataOutMoved != NULL) *dataOutMoved = updateLen + finalLen;
out:
    CCCryptorRelease(cryptor);
    return retval;
}
NSData *CCCryptDataAdvanced(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,CCKeySize keySize,NSData *dataIn,NSData *key,NSData *iv) {
    BOOL keySizeIsValid = NO;
    switch (alg) {
        case kCCAlgorithmAES :keySizeIsValid = keySize == kCCKeySizeAES128 ||
                                               keySize == kCCKeySizeAES192 ||
                                               keySize == kCCKeySizeAES256;    break;
        case kCCAlgorithmDES :keySizeIsValid = keySize == kCCKeySizeDES;       break;
        case kCCAlgorithm3DES:keySizeIsValid = keySize == kCCKeySize3DES;      break;
        case kCCAlgorithmCAST:keySizeIsValid = keySize >= kCCKeySizeMinCAST &&
                                               keySize <= kCCKeySizeMaxCAST;   break;
        case kCCAlgorithmRC4 :keySizeIsValid = keySize >= kCCKeySizeMinRC4  &&
                                               keySize <= kCCKeySizeMaxRC4;    break;
        case kCCAlgorithmRC2 :keySizeIsValid = keySize >= kCCKeySizeMinRC2  &&
                                               keySize <= kCCKeySizeMaxRC2;    break;
        default              :keySizeIsValid = NO;                             break;
    }
    if (!keySizeIsValid) return nil;
    typedef size_t CCBlockSize;
    CCBlockSize blockSize = 0;
    switch(alg) {
        case kCCAlgorithmAES128   : blockSize = kCCBlockSizeAES128;   break;
        case kCCAlgorithmDES      : blockSize = kCCBlockSizeDES;      break;
        case kCCAlgorithm3DES     : blockSize = kCCBlockSize3DES;     break;
        case kCCAlgorithmCAST     : blockSize = kCCBlockSizeCAST;     break;
        case kCCAlgorithmRC4      : blockSize = 1;                    break;
        case kCCAlgorithmRC2      : blockSize = kCCBlockSizeRC2;      break;
        case kCCAlgorithmBlowfish : blockSize = kCCBlockSizeBlowfish; break;
        default                   : blockSize = kCCBlockSizeAES128;   break;
    }
    NSMutableData *dataOut = [NSMutableData dataWithLength:dataIn.length + blockSize];
    size_t dataOutMoved = 0;
    CCCryptorStatus status = CCCryptAdvanced(op, mode, alg, padding, key.bytes, keySize, iv.bytes, dataIn.bytes, dataIn.length, dataOut.mutableBytes, dataOut.length, &dataOutMoved);
    if (status != kCCSuccess) return nil;
    dataOut.length = dataOutMoved;
    return dataOut.copy;
}
NSString *CCCryptStringAdvanced(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding,CCKeySize keySize,NSString *sourceIn,NSString *keyString,NSString *ivString){
    NSData *dataIn = nil;
    switch (op) {
        case kCCEncrypt:
            dataIn = [sourceIn dataUsingEncoding:NSUTF8StringEncoding];
            break;
        case kCCDecrypt:
            dataIn = [[NSData alloc] initWithBase64EncodedString:sourceIn options:kNilOptions];
            break;
        default:
            return nil;
    }
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData  = [ivString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *dataOut = CCCryptDataAdvanced(op, mode, alg, padding, keySize, dataIn, keyData, ivData);
    if (dataOut.length == 0) return nil;
    switch (op) {
        case kCCEncrypt:
            return [dataOut base64EncodedStringWithOptions:kNilOptions];
        case kCCDecrypt:
            return [[NSString alloc] initWithData:dataOut encoding:NSUTF8StringEncoding];
        default:
            return nil;
    }
}
