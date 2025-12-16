import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_4949E243E0DFC150577BFEB9D722C185 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-03"
      version             = "1.0"

      hash                = "a0114420ff98f4f09df676527add4ccaaf4326b4bd0c87b153d1ea71adf50022"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "LAABAI LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "49:49:e2:43:e0:df:c1:50:57:7b:fe:b9:d7:22:c1:85"
      cert_thumbprint     = "B70F2672E4C5231FAE9069969BF8EC1219228078"
      cert_valid_from     = "2023-08-03"
      cert_valid_to       = "2024-08-01"

      country             = "GB"
      state               = "???"
      locality            = "Bargoed"
      email               = "???"
      rdn_serial_number   = "11455947"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "49:49:e2:43:e0:df:c1:50:57:7b:fe:b9:d7:22:c1:85"
      )
}
