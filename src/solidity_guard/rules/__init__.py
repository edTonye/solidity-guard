from .old_pragma import OldPragmaRule
from .reentrancy import ReentrancyRule
from .tx_origin import TxOriginRule
from .unchecked_call import UncheckedCallRule

ALL_RULES = [
    ReentrancyRule(),
    TxOriginRule(),
    UncheckedCallRule(),
    OldPragmaRule(),
]
