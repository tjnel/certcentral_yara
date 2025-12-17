import "pe"

rule MAL_Compromised_Cert_TrickBot_Sectigo_00AFC5522898143AAFAAB7FD52304CF00C {
   meta:
      description         = "Detects TrickBot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-31"
      version             = "1.0"

      hash                = "84175ba73a6a59496e2d020d05a120e9e8e94ac3a4fdea8fc381acda452bb991"
      malware             = "TrickBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "YAN CHING LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c"
      cert_thumbprint     = "10232012CCD37D90EAD875CCD64414D87DE329A5"
      cert_valid_from     = "2021-05-31"
      cert_valid_to       = "2022-05-31"

      country             = "GB"
      state               = "North Humberside"
      locality            = "HULL"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c"
      )
}
