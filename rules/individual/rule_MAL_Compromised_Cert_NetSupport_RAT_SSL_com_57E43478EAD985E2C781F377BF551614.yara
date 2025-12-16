import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_57E43478EAD985E2C781F377BF551614 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-14"
      version             = "1.0"

      hash                = "c241d88e64697f8a7e4a80b10677952bf6df072465e3a75ad5295d010cb5f4d2"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "ACM Software ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "57:e4:34:78:ea:d9:85:e2:c7:81:f3:77:bf:55:16:14"
      cert_thumbprint     = "BC89457220753CA347D15E24C328D24A5886AF13"
      cert_valid_from     = "2024-07-14"
      cert_valid_to       = "2025-07-14"

      country             = "DK"
      state               = "???"
      locality            = "Risskov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "57:e4:34:78:ea:d9:85:e2:c7:81:f3:77:bf:55:16:14"
      )
}
