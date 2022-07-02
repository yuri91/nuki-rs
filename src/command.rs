#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CommandId(u16);
impl CommandId {
    pub fn value(&self) -> u16 {
        self.0
    }
}
pub const REQUEST_DATA: CommandId = CommandId(0x0001);
pub const PUBLIC_KEY: CommandId = CommandId(0x0003);
pub const CHALLENGE: CommandId = CommandId(0x0004);
pub const AUTHORIZATION_AUTHENTICATOR: CommandId = CommandId(0x0005);
pub const AUTHORIZATION_DATA: CommandId = CommandId(0x0006);
pub const AUTHORIZATION_ID: CommandId = CommandId(0x0007);
pub const REMOVE_USER_AUTHORIZATION: CommandId = CommandId(0x0008);
pub const REQUEST_AUTHORIZATION_ENTRIES: CommandId = CommandId(0x0009);
pub const AUTHORIZATION_ENTRY: CommandId = CommandId(0x000A);
pub const AUTHORIZATION_DATA_INVITE: CommandId = CommandId(0x000B);
pub const KEYTURNER_STATES: CommandId = CommandId(0x000C);
pub const LOCK_ACTION: CommandId = CommandId(0x000D);
pub const STATUS: CommandId = CommandId(0x000E);
pub const MOST_RECENT_COMMAND: CommandId = CommandId(0x000F);
pub const OPENINGS_CLOSINGS_SUMMARY: CommandId = CommandId(0x0010);
pub const BATTERY_REPORT: CommandId = CommandId(0x0011);
pub const ERROR_REPORT: CommandId = CommandId(0x0012);
pub const SET_CONFIG: CommandId = CommandId(0x0013);
pub const REQUEST_CONFIG: CommandId = CommandId(0x0014);
pub const CONFIG: CommandId = CommandId(0x0015);
pub const SET_SECURITY_PIN: CommandId = CommandId(0x0019);
pub const REQUEST_CALIBRATION: CommandId = CommandId(0x001A);
pub const REQUEST_REBOOT: CommandId = CommandId(0x001D);
pub const AUTHORIZATION_IDCONFIRMATION: CommandId = CommandId(0x001E);
pub const AUTHORIZATION_IDINVITE: CommandId = CommandId(0x001F);
pub const VERIFY_SECURITY_PIN: CommandId = CommandId(0x0020);
pub const UPDATE_TIME: CommandId = CommandId(0x0021);
pub const UPDATE_USER_AUTHORIZATION: CommandId = CommandId(0x0025);
pub const AUTHORIZATION_ENTRY_COUNT: CommandId = CommandId(0x0027);
pub const REQUEST_LOG_ENTRIES: CommandId = CommandId(0x0031);
pub const LOG_ENTRY: CommandId = CommandId(0x0032);
pub const LOG_ENTRY_COUNT: CommandId = CommandId(0x0033);
pub const ENABLE_LOGGING: CommandId = CommandId(0x0034);
pub const SET_ADVANCED_CONFIG: CommandId = CommandId(0x0035);
pub const REQUEST_ADVANCED_CONFIG: CommandId = CommandId(0x0036);
pub const ADVANCED_CONFIG: CommandId = CommandId(0x0037);
pub const ADD_TIME_CONTROL_ENTRY: CommandId = CommandId(0x0039);
pub const TIME_CONTROL_ENTRY_ID: CommandId = CommandId(0x003A);
pub const REMOVE_TIME_CONTROL_ENTRY: CommandId = CommandId(0x003B);
pub const REQUEST_TIME_CONTROL_ENTRIES: CommandId = CommandId(0x003C);
pub const TIME_CONTROL_ENTRY_COUNT: CommandId = CommandId(0x003D);
pub const TIME_CONTROL_ENTRY: CommandId = CommandId(0x003E);
pub const UPDATE_TIME_CONTROL_ENTRY: CommandId = CommandId(0x003F);
pub const ADD_KEYPAD_CODE: CommandId = CommandId(0x0041);
pub const KEYPAD_CODE_ID: CommandId = CommandId(0x0042);
pub const REQUEST_KEYPAD_CODES: CommandId = CommandId(0x0043);
pub const KEYPAD_CODE_COUNT: CommandId = CommandId(0x0044);
pub const KEYPAD_CODE: CommandId = CommandId(0x0045);
pub const UPDATE_KEYPAD_CODE: CommandId = CommandId(0x0046);
pub const REMOVE_KEYPAD_CODE: CommandId = CommandId(0x0047);
pub const KEYPAD_ACTION: CommandId = CommandId(0x0048);
pub const SIMPLE_LOCK_ACTION: CommandId = CommandId(0x0100);

pub fn parse(cmd: u16) -> anyhow::Result<CommandId> {
    Ok(CommandId(match CommandId(cmd) {
        REQUEST_DATA => cmd,
        PUBLIC_KEY => cmd,
        CHALLENGE => cmd,
        AUTHORIZATION_AUTHENTICATOR => cmd,
        AUTHORIZATION_DATA => cmd,
        AUTHORIZATION_ID => cmd,
        REMOVE_USER_AUTHORIZATION => cmd,
        REQUEST_AUTHORIZATION_ENTRIES => cmd,
        AUTHORIZATION_ENTRY => cmd,
        AUTHORIZATION_DATA_INVITE => cmd,
        KEYTURNER_STATES => cmd,
        LOCK_ACTION => cmd,
        STATUS => cmd,
        MOST_RECENT_COMMAND => cmd,
        OPENINGS_CLOSINGS_SUMMARY => cmd,
        BATTERY_REPORT => cmd,
        ERROR_REPORT => cmd,
        SET_CONFIG => cmd,
        REQUEST_CONFIG => cmd,
        CONFIG => cmd,
        SET_SECURITY_PIN => cmd,
        REQUEST_CALIBRATION => cmd,
        REQUEST_REBOOT => cmd,
        AUTHORIZATION_IDCONFIRMATION => cmd,
        AUTHORIZATION_IDINVITE => cmd,
        VERIFY_SECURITY_PIN => cmd,
        UPDATE_TIME => cmd,
        UPDATE_USER_AUTHORIZATION => cmd,
        AUTHORIZATION_ENTRY_COUNT => cmd,
        REQUEST_LOG_ENTRIES => cmd,
        LOG_ENTRY => cmd,
        LOG_ENTRY_COUNT => cmd,
        ENABLE_LOGGING => cmd,
        SET_ADVANCED_CONFIG => cmd,
        REQUEST_ADVANCED_CONFIG => cmd,
        ADVANCED_CONFIG => cmd,
        ADD_TIME_CONTROL_ENTRY => cmd,
        TIME_CONTROL_ENTRY_ID => cmd,
        REMOVE_TIME_CONTROL_ENTRY => cmd,
        REQUEST_TIME_CONTROL_ENTRIES => cmd,
        TIME_CONTROL_ENTRY_COUNT => cmd,
        TIME_CONTROL_ENTRY => cmd,
        UPDATE_TIME_CONTROL_ENTRY => cmd,
        ADD_KEYPAD_CODE => cmd,
        KEYPAD_CODE_ID => cmd,
        REQUEST_KEYPAD_CODES => cmd,
        KEYPAD_CODE_COUNT => cmd,
        KEYPAD_CODE => cmd,
        UPDATE_KEYPAD_CODE => cmd,
        REMOVE_KEYPAD_CODE => cmd,
        KEYPAD_ACTION => cmd,
        SIMPLE_LOCK_ACTION => cmd,
        _ => return Err(anyhow::anyhow!("Unknown command: {:x}", cmd)),
    }))
}

impl std::fmt::Display for CommandId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match *self {
            REQUEST_DATA => "REQUEST_DATA",
            PUBLIC_KEY => "PUBLIC_KEY",
            CHALLENGE => "CHALLENGE",
            AUTHORIZATION_AUTHENTICATOR => "AUTHORIZATION_AUTHENTICATOR",
            AUTHORIZATION_DATA => "AUTHORIZATION_DATA",
            AUTHORIZATION_ID => "AUTHORIZATION_ID",
            REMOVE_USER_AUTHORIZATION => "REMOVE_USER_AUTHORIZATION",
            REQUEST_AUTHORIZATION_ENTRIES => "REQUEST_AUTHORIZATION_ENTRIES",
            AUTHORIZATION_ENTRY => "AUTHORIZATION_ENTRY",
            AUTHORIZATION_DATA_INVITE => "AUTHORIZATION_DATA_INVITE",
            KEYTURNER_STATES => "KEYTURNER_STATES",
            LOCK_ACTION => "LOCK_ACTION",
            STATUS => "STATUS",
            MOST_RECENT_COMMAND => "MOST_RECENT_COMMAND",
            OPENINGS_CLOSINGS_SUMMARY => "OPENINGS_CLOSINGS_SUMMARY",
            BATTERY_REPORT => "BATTERY_REPORT",
            ERROR_REPORT => "ERROR_REPORT",
            SET_CONFIG => "SET_CONFIG",
            REQUEST_CONFIG => "REQUEST_CONFIG",
            CONFIG => "CONFIG",
            SET_SECURITY_PIN => "SET_SECURITY_PIN",
            REQUEST_CALIBRATION => "REQUEST_CALIBRATION",
            REQUEST_REBOOT => "REQUEST_REBOOT",
            AUTHORIZATION_IDCONFIRMATION => "AUTHORIZATION_IDCONFIRMATION",
            AUTHORIZATION_IDINVITE => "AUTHORIZATION_IDINVITE",
            VERIFY_SECURITY_PIN => "VERIFY_SECURITY_PIN",
            UPDATE_TIME => "UPDATE_TIME",
            UPDATE_USER_AUTHORIZATION => "UPDATE_USER_AUTHORIZATION",
            AUTHORIZATION_ENTRY_COUNT => "AUTHORIZATION_ENTRY_COUNT",
            REQUEST_LOG_ENTRIES => "REQUEST_LOG_ENTRIES",
            LOG_ENTRY => "LOG_ENTRY",
            LOG_ENTRY_COUNT => "LOG_ENTRY_COUNT",
            ENABLE_LOGGING => "ENABLE_LOGGING",
            SET_ADVANCED_CONFIG => "SET_ADVANCED_CONFIG",
            REQUEST_ADVANCED_CONFIG => "REQUEST_ADVANCED_CONFIG",
            ADVANCED_CONFIG => "ADVANCED_CONFIG",
            ADD_TIME_CONTROL_ENTRY => "ADD_TIME_CONTROL_ENTRY",
            TIME_CONTROL_ENTRY_ID => "TIME_CONTROL_ENTRY_ID",
            REMOVE_TIME_CONTROL_ENTRY => "REMOVE_TIME_CONTROL_ENTRY",
            REQUEST_TIME_CONTROL_ENTRIES => "REQUEST_TIME_CONTROL_ENTRIES",
            TIME_CONTROL_ENTRY_COUNT => "TIME_CONTROL_ENTRY_COUNT",
            TIME_CONTROL_ENTRY => "TIME_CONTROL_ENTRY",
            UPDATE_TIME_CONTROL_ENTRY => "UPDATE_TIME_CONTROL_ENTRY",
            ADD_KEYPAD_CODE => "ADD_KEYPAD_CODE",
            KEYPAD_CODE_ID => "KEYPAD_CODE_ID",
            REQUEST_KEYPAD_CODES => "REQUEST_KEYPAD_CODES",
            KEYPAD_CODE_COUNT => "KEYPAD_CODE_COUNT",
            KEYPAD_CODE => "KEYPAD_CODE",
            UPDATE_KEYPAD_CODE => "UPDATE_KEYPAD_CODE",
            REMOVE_KEYPAD_CODE => "REMOVE_KEYPAD_CODE",
            KEYPAD_ACTION => "KEYPAD_ACTION",
            SIMPLE_LOCK_ACTION => "SIMPLE_LOCK_ACTION",
            _ => unreachable!("invalid command value"),
        };
        write!(f, "{}", id)
    }
}
