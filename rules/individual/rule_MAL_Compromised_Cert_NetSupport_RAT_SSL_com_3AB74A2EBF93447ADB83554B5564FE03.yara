import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_3AB74A2EBF93447ADB83554B5564FE03 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-19"
      version             = "1.0"

      hash                = "e7ec6934a362bcdb3d6c686c39d6130174622000f3fdda9274a6d7d2418e515f"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "IMPERIOUS TECHNOLOGIES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "3a:b7:4a:2e:bf:93:44:7a:db:83:55:4b:55:64:fe:03"
      cert_thumbprint     = "21A97512A2959B0E74729BE220102AEF1DCF56FD"
      cert_valid_from     = "2023-05-19"
      cert_valid_to       = "2024-05-17"

      country             = "GB"
      state               = "???"
      locality            = "Ringwood"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "3a:b7:4a:2e:bf:93:44:7a:db:83:55:4b:55:64:fe:03"
      )
}
