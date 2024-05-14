// https://github.com/intel/tdx-tools/blob/tdx-mid-stream/attestation/pytdxmeasure/pytdxmeasure/utility.py#L87
// https://lwn.net/Articles/906357/

const TDX_REPORTDATA_LEN: usize = 64;
const TDX_REPORT_LEN: usize = 1024;

#[derive(Debug)]
#[repr(C)]
struct TdReportStruct {
    report_mac_struct: ReportMac,

    /// additional attestable elements in the TD's TCB that are not reflected in the
    /// REPORTMCSTRUCT.CPUSVN -- includes the Intel TDX module measurements
    tee_tcb_info: [u8; 239],

    /// Reserved.
    _reserved: [u8; 17],

    /// TD's attestable properties
    td_info: TdInfo,
}

#[derive(Debug)]
#[repr(C)]
struct ReportMac {
    /// Type header structure
    report_type: ReportType,

    /// Reserved.
    _reserved1: [u8; 12],

    /// CPU SVN
    cpusvn: [u8; 16],

    /// SHA384 of TEE_TCB_INFO
    tee_tcb_info_hash: [u8; 48],

    /// SHA384 of TEE_INFO: a TEE-specific info structure or 0 if no TEE is represented
    tee_info_hash: [u8; 48],

    /// A set of data used for communication between the caller and the target
    report_data: [u8; 64],

    /// Reserved.
    _reserved2: [u8; 32],

    /// The MAC over the REPORTMACSTRUCT with model-specific MAC
    mac: [u8; 32],
}

#[derive(Debug)]
#[repr(C)]
struct ReportType {
    /// Trusted Execution Environment (TEE) type
    ///
    /// value:
    ///     0x00: SGX
    ///     0x7F-0x01: Reserved (TEE implemented by CPU)
    ///     0x80: Reserved (TEE implemented by a SEAM module)
    ///     0x81: TDX
    ///     0xFF-0x82: Reserved (TEE implemented by a SEAM module)
    tee_type: u8,

    /// Type-specific subtype
    ///
    /// value:
    ///     0: Standard TDX report
    ///     Other: Reserved
    subtype: u8,

    /// Type-specific version:
    ///
    /// For TDX, VERSION might have the following values:
    ///     0: There are no bound nor pre-bound service TDs. TDINFO_STRUCT.SERVTD_HASH is not used
    ///     1: TDINFO_STRUCT.SERVTD_HASH is used
    version: u8,

    /// Reserved.
    _reserved: u8,
}

#[derive(Debug)]
#[repr(C)]
struct TdInfo {
    /// TDX Guest attributes
    attr: [u8; 8],
    /// Extended features allowed mask
    xfam: u64,
    /// Build time measurement register
    mrtd: [u64; 6],
    /// Software-defined ID for the guest owner
    mrconfigid: [u64; 6],
    /// Software-defined ID for non-owner-defined configuration of the guest - (run-time or OS
    /// configuration)
    mrowner: [u64; 6],
    /// Software-defined ID for non-owner-defined configuration of the guest - (specific to the
    /// workload)
    mrownerconfig: [u64; 6],
    /// Run time measurement registers
    rtmr: [u64; 24],
    /// Reserved.
    reserved: [u64; 14],
}

#[derive(Debug)]
#[repr(C)]
struct TdxReportRequest {
    report_data: [u8; TDX_REPORTDATA_LEN],
    td_report: [u8; TDX_REPORT_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn get_td_report() {
        // build the request
        let req = TdxReportRequest {
            report_data: [25; TDX_REPORTDATA_LEN],
            td_report: [0; TDX_REPORT_LEN],
        };

        // open file
        let guest_device = std::fs::File::open("/dev/tdx_guest").unwrap();

        // build the ioctl
        ioctl_readwrite!(get_td_1_5_report, b'T', 1, TdxReportRequest);

        // make ioctl call
        let res = unsafe {
            get_td_1_5_report(
                guest_device.as_raw_fd(),
                std::ptr::addr_of!(req) as *mut TdxReportRequest,
            )
        };

        // print requst to verify
        match res {
            Err(e) => panic!("Unable to retrieve TD report: {}", e),
            Ok(_) => panic!("TD Report result: \n{:#?}", req),
        }
    }
}
