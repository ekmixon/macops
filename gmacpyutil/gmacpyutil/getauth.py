"""Methods to retrieve and validate auth information."""

import getpass
import re
from . import cocoadialog


OTP_REGEX = re.compile(
    u'^[a-zA-Z0-9&\u00e9"\'(\u00e8_\u00e7\u00e0\u00a7!]{6,9}$',
    re.UNICODE)


def _GetPasswordGUI(title='Password', text='Enter your password', hidden=True):
  """Application and platform specific GUI getpass.

  Args:
    title: string for title of window
    text: string for promp text
    hidden: bool whether to show user input
  Returns:
    password as string
  """
  pwprompt = cocoadialog.Standard_InputBox()
  if hidden:
    pwprompt.SetPasswordBox()
  pwprompt._title = title  # pylint: disable=protected-access
  pwprompt._informative_text = text  # pylint: disable=protected-access
  output = pwprompt.Show()
  return output.split('\n')[1]


def _GetPasswordInteractively(prompt='Password: ', hidden=True,
                              input_fn=raw_input):
  """Application specific getpass.

  Args:
    prompt: string with the password prompt
    hidden: bool whether to show user input
    input_fn: function to get user input, used in testing
  Returns:
    password as string
  Raises:
    KeyboardInterrupt: User cancelled request with keyboard interrupt (Ctrl+C)
    EOFError: If password is empty
  """
  return getpass.getpass(prompt) if hidden else input_fn(prompt)


def GetAuthToken(prompt='Password: ', title='Password',
                 text='Enter your password', hidden=True, gui=False,
                 validator=None):
  """Gets a password or other auth token on console or gui with custom prompts.

  Args:
    prompt: string with the password prompt
    title: string for title of window
    text: string for promp text
    hidden: bool whether to show user input
    gui: bool, whether to use GUI
    validator: compiled regex
  Returns:
    password as string
  Raises:
    KeyboardInterrupt: User cancelled request with keyboard interrupt (Ctrl+C)
    EOFError: If password is empty
  """
  while True:
    if gui:
      password = _GetPasswordGUI(title=title, text=text, hidden=hidden)
    else:
      password = _GetPasswordInteractively(prompt=prompt, hidden=hidden)
    if validator and validator.match(password) or not validator:
      return password


def GetPassword(prompt='Password: ', title='Password',
                text='Enter your password', gui=False, validator=None):
  """Helper function to get a password."""
  return GetAuthToken(prompt=prompt, title=title, text=text, hidden=True,
                      gui=gui, validator=validator)


def GetOTP(prompt='OTP: ', title='One-Time Password', text='Enter an OTP',
           gui=False, validator=OTP_REGEX):
  """Helper function to get an OTP."""
  return GetAuthToken(prompt=prompt, title=title, text=text, hidden=False,
                      gui=gui, validator=validator)
