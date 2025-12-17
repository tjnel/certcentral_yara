import "pe"

rule MAL_Compromised_Cert_Netfilim_Sectigo_00C04F5D17AF872CB2C37E3367FE761D0D {
   meta:
      description         = "Detects Netfilim with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-12"
      version             = "1.0"

      hash                = "0bafde9b22d7147de8fdb852bcd529b1730acddc9eb71316b66c180106f777f5"
      malware             = "Netfilim"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DES SP Z O O"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"
      cert_thumbprint     = "255B36617C0D1C0AFF3B819CE9DC2CD0F0A67A8A"
      cert_valid_from     = "2020-07-12"
      cert_valid_to       = "2021-07-12"

      country             = "PL"
      state               = "???"
      locality            = "Krakow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"
      )
}
