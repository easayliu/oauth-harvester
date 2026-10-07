"""IMAP 公共工具。"""

import imaplib
import logging

logger = logging.getLogger(__name__)


def imap_delete_uid(imap: imaplib.IMAP4, uid) -> bool:
    """删除当前选中邮箱里的指定 UID 邮件，成功返回 True。删除失败只告警，不影响已提取的结果。

    服务器支持 UIDPLUS 时用 UID EXPUNGE 只清这一封；否则退回普通 EXPUNGE
    （会顺带清掉 INBOX 里其它已标 \\Deleted 的邮件）。
    注：Gmail 默认把 INBOX 里 expunge 的邮件当作「归档」而非进垃圾箱，取决于其 IMAP 设置。"""
    uid_s = uid.decode() if isinstance(uid, bytes) else str(uid)
    try:
        typ, _ = imap.uid("store", uid, "+FLAGS", r"(\Deleted)")
        if typ != "OK":
            logger.warning(f"标记删除失败 UID={uid_s}: {typ}")
            return False
        if "UIDPLUS" in imap.capabilities:
            imap.uid("expunge", uid)
        else:
            imap.expunge()
        logger.info(f"已删除登录邮件 UID={uid_s}")
        return True
    except Exception as e:
        logger.warning(f"删除登录邮件失败 UID={uid_s}: {e}")
        return False
