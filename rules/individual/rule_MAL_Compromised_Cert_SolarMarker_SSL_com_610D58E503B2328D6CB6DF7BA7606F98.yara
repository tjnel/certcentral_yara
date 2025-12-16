import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_610D58E503B2328D6CB6DF7BA7606F98 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-16"
      version             = "1.0"

      hash                = "21646416f656f7b4da74214f2a33bc19733bdd30525381ceb66bb87a6ceb32d6"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "BELLANN BOARD & PACKAGING CO.LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "61:0d:58:e5:03:b2:32:8d:6c:b6:df:7b:a7:60:6f:98"
      cert_thumbprint     = "F8C4EDE315C5CA98B13BF67EB6DEA79FFD00DFB6"
      cert_valid_from     = "2023-08-16"
      cert_valid_to       = "2024-08-15"

      country             = "GB"
      state               = "???"
      locality            = "Burnley"
      email               = "???"
      rdn_serial_number   = "06368556"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "61:0d:58:e5:03:b2:32:8d:6c:b6:df:7b:a7:60:6f:98"
      )
}
