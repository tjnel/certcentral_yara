import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_13CC954B236638C54A9A92AB999F933B {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-22"
      version             = "1.0"

      hash                = "b776bec01001adee37fcc61fb6292b832e59636825d78ad4bd90f3b6a2bbf07e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "福州隋德洛贸易有限公司"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "13:cc:95:4b:23:66:38:c5:4a:9a:92:ab:99:9f:93:3b"
      cert_thumbprint     = "7463BB75B792A99E6E8372ADEB5832C50071BA9D"
      cert_valid_from     = "2024-05-22"
      cert_valid_to       = "2027-05-22"

      country             = "CN"
      state               = "Fujian"
      locality            = "Fuzhou"
      email               = "???"
      rdn_serial_number   = "91350102MA31GBQN4D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "13:cc:95:4b:23:66:38:c5:4a:9a:92:ab:99:9f:93:3b"
      )
}
