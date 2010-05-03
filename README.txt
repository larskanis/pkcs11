= PKCS #11/Ruby Interface

* http://coderepos.org/share/log/lang/ruby/pkcs11-ruby

This module allows Ruby programs to interface with "RSA Security Inc. 
PKCS #11 Cryptographic Token Interface (Cryptoki)".
You must have the PKCS #11 v2.20 implementation library installed in
order to use this module.

Right now, this module works on the Unix like operating systems and win32.

== Compilation

  rake native gem

== Installation

  gem install pkcs11

== Usage

PKCS11.new requires suitable PKCS #11 implementation for your smart-cards.

  require "rubygems"
  require "pkcs11"

  pkcs11 = PKCS11.new("/path/to/pkcs11.so")
  slots = pkcs11.C_GetSlotList(true)
  slot = slots.first
  info = pkcs11.C_GetSlotInfo(slot)
  p [info.slotDescription, info.manufacturerID,
     info.flags, info.firmwareVersion, info.hardwareVersion]
  flags = PKCS11::CKF_SERIAL_SESSION|PKCS11::CKF_RW_SESSION
  session = pkcs11.C_OpenSession(slot, flags)
  pkcs11.C_Login(session, PKCS11::CKU_USER, "1234")
  ...
  pkcs11.C_Logout(session)
  pkcs11.C_CloseSession(session)

Detail information for the API specification is provided by RSA Security Inc.
Please refer the URL: http://www.rsa.com/rsalabs/node.asp?id=2133.

== ToDo

 * unit testing (with mozilla softoken)
 * implement all functions/structs
 * sample code

== Development Status

STATE   FUNCTION               NOTE
------  ---------------------  ----------------------------------------
N/A     C_Initialize           called in PKCS11#initialize("/path/to/pk11lib")
N/A     C_Finalize             called in GC
DONE    C_GetInfo
N/A     C_GetFunctionList      internal use only
DONE    C_GetSlotList
DONE    C_GetSlotInfo
DONE    C_GetTokenInfo
DONE    C_GetMechanismList
DONE    C_GetMechanismInfo
DONE    C_InitToken
DONE    C_InitPIN
DONE    C_SetPIN
DONE    C_OpenSession
DONE    C_CloseSession
DONE    C_CloseAllSessions
DONE    C_GetSessionInfo
DONE    C_GetOperationState
DONE    C_SetOperationState
DONE    C_Login
DONE    C_Logout
DONE    C_CreateObject
N/A     C_CopyObject           use C_GetAttributeValue and C_CreateObject
DONE    C_DestroyObject
DONE    C_GetObjectSize
DONE    C_GetAttributeValue
DONE    C_SetAttributeValue
DONE    C_FindObjectsInit
DONE    C_FindObjects
DONE    C_FindObjectsFinal
DONE    C_EncryptInit
DONE    C_Encrypt
DONE    C_EncryptUpdate
DONE    C_EncryptFinal
DONE    C_DecryptInit
DONE    C_Decrypt
DONE    C_DecryptUpdate
DONE    C_DecryptFinal
DONE    C_DigestInit
DONE    C_Digest
DONE    C_DigestUpdate
DONE    C_DigestKey
DONE    C_DigestFinal
DONE    C_SignInit
DONE    C_Sign
DONE    C_SignUpdate
DONE    C_SignFinal
DONE    C_SignRecoverInit
DONE    C_SignRecover
DONE    C_VerifyInit
DONE    C_Verify
DONE    C_VerifyUpdate
DONE    C_VerifyFinal
DONE    C_VerifyRecoverInit
DONE    C_VerifyRecover
DONE    C_DigestEncryptUpdate
DONE    C_DecryptDigestUpdate
DONE    C_SignEncryptUpdate
DONE    C_DecryptVerifyUpdate
DONE    C_GenerateKey
DONE    C_GenerateKeyPair
DONE    C_WrapKey
DONE    C_UnwrapKey
DONE    C_DeriveKey
DONE    C_SeedRandom
DONE    C_GenerateRandom
N/A     C_GetFunctionStatus    legacy function
N/A     C_CancelFunction       legacy function
DONE    C_WaitForSlotEvent
