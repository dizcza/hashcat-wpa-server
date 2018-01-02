# encoding=utf-8

import os
import slacker

from app.app_logger import logger


class SlackSender(object):

    def __init__(self):
        slack_token = os.environ.get("SLACK_TOKEN", None)
        if slack_token:
            self.slacker = slacker.Slacker(slack_token)
        else:
            self.slacker = None
            logger.warning("To receive slack bot messages, setup 'SLACK_TOKEN' env")

    def send(self, response: dict, channel="#general"):
        if self.slacker is None:
            return
        try:
            message_pretty = ""
            for key, value in response.items():
                message_pretty += "`{}`: {}\n".format(key, str(value))
            slack_resp = self.slacker.chat.post_message(channel, message_pretty)
            logger.debug(slack_resp)
        except slacker.Error as error:
            logger.error(error)
