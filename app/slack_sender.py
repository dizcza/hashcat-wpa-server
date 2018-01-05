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
        self.channel_id = {}
        for channel_info in self.slacker.channels.list().body["channels"]:
            self.channel_id[channel_info["name"]] = channel_info["id"]

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

    def list_cracked(self):
        messages = self.slacker.channels.history(self.channel_id["cracked"], count=1000).body["messages"]
        cracked_wpa = set([])
        key_pattern = "`key`:"
        for msg in messages:
            text = msg["text"]
            if key_pattern not in text:
                continue
            start = text.index(key_pattern) + len(key_pattern)
            end = text.index('\n', start)
            password_parts = text[start: end].split(':')
            if len(password_parts) != 5:
                # wrong/invalid field
                continue
            essid, password = password_parts[3], password_parts[4]
            cracked_wpa.add("{}:{}".format(essid, password))
        logger.debug("Cracked {} WPA2:\n{}".format(len(cracked_wpa), '\n'.join(cracked_wpa)))
        self.slacker.chat.post_message("#general", '\n'.join(cracked_wpa))
        return cracked_wpa


if __name__ == '__main__':
    sender = SlackSender()
    sender.list_cracked()
