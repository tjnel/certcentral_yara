import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_15D82B35761FE064DF2BC72C62D69A04 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-03"
      version             = "1.0"

      hash                = "4e25b7cc56cbf7a5670d696f9833a794885b6698e4d9b002957ea09645af763d"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Laks Tech Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "15:d8:2b:35:76:1f:e0:64:df:2b:c7:2c:62:d6:9a:04"
      cert_thumbprint     = "B9C03DF2C57C398DA548FCC57F7B46E6BA8E2780"
      cert_valid_from     = "2024-07-03"
      cert_valid_to       = "2025-07-03"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "15:d8:2b:35:76:1f:e0:64:df:2b:c7:2c:62:d6:9a:04"
      )
}
