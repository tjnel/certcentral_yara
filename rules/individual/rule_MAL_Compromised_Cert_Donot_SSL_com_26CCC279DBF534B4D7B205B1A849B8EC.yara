import "pe"

rule MAL_Compromised_Cert_Donot_SSL_com_26CCC279DBF534B4D7B205B1A849B8EC {
   meta:
      description         = "Detects Donot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-04"
      version             = "1.0"

      hash                = "4d036e0a517774ba8bd31df522a8d9e327202548a5753e5de068190582758680"
      malware             = "Donot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ebo Sky Tech Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "26:cc:c2:79:db:f5:34:b4:d7:b2:05:b1:a8:49:b8:ec"
      cert_thumbprint     = "EC43D029AC2552E38A27421D30FBE51AE4F09DF2"
      cert_valid_from     = "2024-12-04"
      cert_valid_to       = "2025-12-04"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Vancouver"
      email               = "???"
      rdn_serial_number   = "1136715-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "26:cc:c2:79:db:f5:34:b4:d7:b2:05:b1:a8:49:b8:ec"
      )
}
