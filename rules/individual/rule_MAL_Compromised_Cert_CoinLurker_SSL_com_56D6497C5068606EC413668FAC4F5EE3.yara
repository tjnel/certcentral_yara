import "pe"

rule MAL_Compromised_Cert_CoinLurker_SSL_com_56D6497C5068606EC413668FAC4F5EE3 {
   meta:
      description         = "Detects CoinLurker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-22"
      version             = "1.0"

      hash                = "487156ae20cc6d8e7d922cebe35b197c28ae43134f7e04c5f6bd0f3e164a7120"
      malware             = "CoinLurker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hunan Exotic Hotel Management Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "56:d6:49:7c:50:68:60:6e:c4:13:66:8f:ac:4f:5e:e3"
      cert_thumbprint     = "9AD448726590D64E247266E0B6FF1524FA094A51"
      cert_valid_from     = "2024-01-22"
      cert_valid_to       = "2025-01-21"

      country             = "CN"
      state               = "Hunan"
      locality            = "Changsha"
      email               = "???"
      rdn_serial_number   = "914301035765540498"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "56:d6:49:7c:50:68:60:6e:c4:13:66:8f:ac:4f:5e:e3"
      )
}
