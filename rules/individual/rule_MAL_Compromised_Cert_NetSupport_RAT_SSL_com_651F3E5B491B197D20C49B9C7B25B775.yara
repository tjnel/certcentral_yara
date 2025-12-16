import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_651F3E5B491B197D20C49B9C7B25B775 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-04"
      version             = "1.0"

      hash                = "686495bd2f04f2402b3543efd574a707caac0003dd682909db87da286173e771"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Rhynedahll Software LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "65:1f:3e:5b:49:1b:19:7d:20:c4:9b:9c:7b:25:b7:75"
      cert_thumbprint     = "97A037320A2AC3A7C4A41FA7B53AFC6EC886450B"
      cert_valid_from     = "2023-05-04"
      cert_valid_to       = "2024-05-03"

      country             = "US"
      state               = "Louisiana"
      locality            = "Doyline"
      email               = "???"
      rdn_serial_number   = "42115577K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "65:1f:3e:5b:49:1b:19:7d:20:c4:9b:9c:7b:25:b7:75"
      )
}
