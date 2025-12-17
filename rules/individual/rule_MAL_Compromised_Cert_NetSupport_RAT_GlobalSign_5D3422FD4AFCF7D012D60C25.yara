import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_5D3422FD4AFCF7D012D60C25 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-22"
      version             = "1.0"

      hash                = "58c12cdf6fd101f2aec69cac01147393f7132de474920aa0cf2a4b95689bc5b7"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "SOFTWARE BYTES LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5d:34:22:fd:4a:fc:f7:d0:12:d6:0c:25"
      cert_thumbprint     = "DC656AF416A78304F08264E379DA8AB1DF6C4432"
      cert_valid_from     = "2024-01-22"
      cert_valid_to       = "2025-01-22"

      country             = "GB"
      state               = "Wales"
      locality            = "Cardiff"
      email               = "admin@softwarebytes.uk"
      rdn_serial_number   = "12315026"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5d:34:22:fd:4a:fc:f7:d0:12:d6:0c:25"
      )
}
