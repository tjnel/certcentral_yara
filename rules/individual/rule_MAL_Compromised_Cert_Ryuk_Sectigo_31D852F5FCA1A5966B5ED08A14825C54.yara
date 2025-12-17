import "pe"

rule MAL_Compromised_Cert_Ryuk_Sectigo_31D852F5FCA1A5966B5ED08A14825C54 {
   meta:
      description         = "Detects Ryuk with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-04"
      version             = "1.0"

      hash                = "05e06709523fd798da963c2c24254de0fcca6c57e1052996798ecc74ff43b41f"
      malware             = "Ryuk"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BBT KLA d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54"
      cert_thumbprint     = "A657B8F2EFEA32E6A1D46894764B7A4F82AD0B56"
      cert_valid_from     = "2021-02-04"
      cert_valid_to       = "2022-02-04"

      country             = "SI"
      state               = "???"
      locality            = "Maribor"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54"
      )
}
