import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_DigiCert_0AB6F755FFA3C3F19E380DDFFE37F19D {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-17"
      version             = "1.0"

      hash                = "7748483b44afcdd7fbda3501c25e4ebeff29b9733f70c944a7ca1b3701b87e85"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Creative Force ApS"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA"
      cert_serial         = "0a:b6:f7:55:ff:a3:c3:f1:9e:38:0d:df:fe:37:f1:9d"
      cert_thumbprint     = "5A17CDD78C7EAD36EC986BFE49FE7552D44C8B3B"
      cert_valid_from     = "2021-01-17"
      cert_valid_to       = "2022-01-20"

      country             = "DK"
      state               = "???"
      locality            = "Holstebro"
      email               = "???"
      rdn_serial_number   = "41956895"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA" and
         sig.serial == "0a:b6:f7:55:ff:a3:c3:f1:9e:38:0d:df:fe:37:f1:9d"
      )
}
