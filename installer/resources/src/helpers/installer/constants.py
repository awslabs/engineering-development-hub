# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0   

import logging
from questionary import Style

SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")

EDH_LOG_STYLES = {
    logging.DEBUG: ("#8a9bb8", "DEBUG"),
    logging.INFO: ("#4db8ff", "INFO"),
    SUCCESS: ("#00cc66", "SUCCESS"),
    logging.WARNING: ("#ffcc00", "WARNING"),
    logging.ERROR: ("#ff6b6b", "ERROR"),
    logging.CRITICAL: ("#ff6b6b bold", "CRITICAL"),
}

EDH_STYLE = Style(
    [
        ("qmark", "fg:#ffcc00 bold"),
        ("question", "fg:#e8eef7 bold"),
        ("answer", "fg:#4db8ff bold"),
        ("pointer", "fg:#ffcc00 bold"),
        ("highlighted", "fg:#232f3e bg:#ffcc00 bold"),
        ("selected", "fg:#4db8ff bold"),
        ("text", "fg:#e8eef7"),
        ("separator", "fg:#4a5875"),
        ("instruction", "italic fg:#8a9bb8"),
        ("disabled", "fg:#4a5875 italic"),
    ]
)


SOCA_ASCII = (
    "[bold #00cc66]"
    r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢦⡀⠉⠙⢦⡀⠀⠀⣀⣠⣤⣄⣀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⡤⠤⠴⠶⠤⠤⢽⣦⡀⠀⢹⡴⠚⠁⠀⢀⣀⣈⣳⣄⠀⠀
⠀⠀⠀⠀⠀⢠⠞⣁⡤⠴⠶⠶⣦⡄⠀⠀⠀⠀⠀⠀⠀⠶⠿⠭⠤⣄⣈⠙⠳⠀
⠀⠀⠀⠀⢠⡿⠋⠀⠀⢀⡴⠋⠁⠀⣀⡖⠛⢳⠴⠶⡄⠀⠀⠀⠀⠀⠈⠙⢦⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡴⠋⣠⠴⠚⠉⠉⣧⣄⣷⡀⢀⣿⡀⠈⠙⠻⡍⠙⠲⢮⣧
⠀⠀⠀⠀⠀⠀⠀⡞⣠⠞⠁⠀⠀⠀⣰⠃⠀⣸⠉⠉⠀⠙⢦⡀⠀⠸⡄⠀⠈⠟
⠀⠀⠀⠀⠀⠀⢸⠟⠁⠀⠀⠀⠀⢠⠏⠉⢉⡇⠀⠀⠀⠀⠀⠉⠳⣄⢷⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠤⠤⢼⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠉⠉⠉⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣀⣀⣀⣻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⣀⡤⠤⠤⣿⠉⠉⠉⠘⣧⠤⢤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡤⠖⠋⠉⠀⠀⠀⠀⠀⠙⠲⠤⠤⠴⠚⠁⠀⠀⠀⠉⠉⠓⠦⣄⠀⠀⠀
⢀⡞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣄⠀
⠘⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠒⠚⠀
"""
    "[bold #ffcc00]"
    r"""
  ███████  ██████   ██████  █████
  ██      ██    ██ ██      ██   ██
  ███████ ██    ██ ██      ███████
       ██ ██    ██ ██      ██   ██
  ███████  ██████   ██████ ██   ██
"""
    "[/]"
)

EDH_ASCII = r"""
 ██████████    ██████████      █████   █████
░░███░░░░░█   ░░███░░░░███    ░░███   ░░███ 
 ░███  █ ░     ░███   ░░███    ░███    ░███ 
 ░██████       ░███    ░███    ░███████████ 
 ░███░░█       ░███    ░███    ░███░░░░░███ 
 ░███ ░   █    ░███    ███     ░███    ░███ 
 ██████████    ██████████      █████   █████
░░░░░░░░░░    ░░░░░░░░░░      ░░░░░   ░░░░░
"""
