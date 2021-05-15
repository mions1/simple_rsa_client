""" Author: Simone Mione
"""

from os import path
import PyQt5.QtWidgets as qt
import PyQt5.QtGui as qtg

import rsa_core as rsa

class RSAGui(qt.QGridLayout):
	""" Handle application.
		Create layouts and widgets, connect buttons and
		handle their functions.
	"""

	def __init__(self):
		""" Main class, application
		"""
		super().__init__()

	def init(self):

		#-------------- Frame input text -----------------------------------------
		self._f_input_text = qt.QHBoxLayout()
		self._tb_input = qt.QTextEdit()
		
		self._tb_input.setPlaceholderText("Input text")
		self._f_input_text.addWidget(self._tb_input)

		#-------------- Frame enc/dec buttons -----------------------------------------
		self._f_enc_dec_buttons = qt.QHBoxLayout()

		self._b_decrypt = qt.QPushButton("Decrypt")
		self._b_encrypt = qt.QPushButton("Encrypt")

		self._f_enc_dec_buttons.addWidget(self._b_encrypt)
		self._f_enc_dec_buttons.addWidget(self._b_decrypt)

		#-------------- Frame output text -----------------------------------------
		self._f_output_text = qt.QVBoxLayout()
		self._tb_output = qt.QTextEdit()

		self._f_output_buttons = qt.QHBoxLayout()
		self._b_copy_to_clipboard = qt.QPushButton("Copy output to clipboard")
		self._b_switch_input_output = qt.QPushButton("Switch input/output")
		self._f_output_buttons.addWidget(self._b_copy_to_clipboard)
		self._f_output_buttons.addWidget(self._b_switch_input_output)

		self._tb_output.setPlaceholderText("Output text")
		self._f_output_text.addWidget(self._tb_output)
		self._f_output_text.addLayout(self._f_output_buttons)



		#-------------- Frame keys generation -----------------------------------------
		self._f_keys = qt.QVBoxLayout()

		self._e_public_key = qt.QTextEdit()
		self._e_public_key.setPlaceholderText("Public key")

		self._e_private_key = qt.QTextEdit()
		self._e_private_key.setPlaceholderText("Private key")

		self._f_keys_buttons = qt.QHBoxLayout()
		self._b_generate = qt.QPushButton("Key generation")
		self._b_get_keys_from_file = qt.QPushButton("Get from files")

		self._f_keys_buttons.addWidget(self._b_generate)
		self._f_keys_buttons.addWidget(self._b_get_keys_from_file)
		self._f_keys.addWidget(self._e_public_key)
		self._f_keys.addWidget(self._e_private_key)
		self._f_keys.addLayout(self._f_keys_buttons)

		#---------- <ADD HERE OTHER FRAMES AND WIDGETS TO CREATE> -------------

		self._b_switch_input_output.clicked.connect(lambda: self.b_switch_input_output())
		self._b_copy_to_clipboard.clicked.connect(lambda: self.b_copy_to_clipboard())
		self._b_generate.clicked.connect(lambda: self.b_generate_keys())
		self._b_get_keys_from_file.clicked.connect(lambda: self.b_get_from_file())
		self._b_encrypt.clicked.connect(lambda: self.b_encrypt())
		self._b_encrypt.clicked.connect(lambda: self.b_encrypt())
		self._b_decrypt.clicked.connect(lambda: self.b_decrypt())


		self.addLayout(self._f_keys, 0,0,3,1)
		
		self.addLayout(self._f_input_text, 0,2,2,1)
		self.addLayout(self._f_enc_dec_buttons, 2,2)
		self.addLayout(self._f_output_text, 4,0,3,3)

	def b_generate_keys(self):
		""" Generate new keys when click the button.
		    It crate also two files: public_key and private_key.
			private_key is exported with passphrase="password"
		"""
		self.keys = rsa.generate_keys()
		self.show_keys()
	
	def b_get_from_file(self):
		""" Get keys from file when click the button.
		    It supposes that "public_key" and "private_key" file exist.
			They must be generate by this app since private_key is protected by passphrase="password".
			If those files don't exist, it performs generate_key.
		"""
		self.keys = rsa.load_keys()
		if not self.keys:
			self.b_generate_keys()
			return
		self.show_keys()

	def show_keys(self):
		""" Writes keys in the textboxes
		"""
		self._e_public_key.setText(str(self.keys["public_key"]))
		self._e_private_key.setText(str(self.keys["private_key"]))

	def b_encrypt(self):
		""" Start encryption.
			Key generation must be performed a priori.
		    If there is no keys, it gets them before the encryption.
		"""
		if not self.keys:
			self.b_get_from_file()

		message = self._tb_input.toPlainText()
		cipher = rsa.encryption(message, self.keys["public_key"])
		self._tb_output.setText(str(cipher))

	def b_decrypt(self):
		""" Start decryption.
			Key generation must be performed a priori.
		    If there is no keys, it gets them before the decryption.
		"""
		if not self.keys:
			self.b_get_from_file()

		cipher = self._tb_input.toPlainText()
		message = rsa.decryption(cipher, self.keys["private_key"])
		self._tb_output.setText(str(message))

	def b_copy_to_clipboard(self):
		text = self._tb_output.toPlainText()
		if text:
			if text != "":
				cb = qt.QApplication.clipboard()
				cb.clear(mode=cb.Clipboard )
				cb.setText(text, mode=cb.Clipboard)

	def b_switch_input_output(self):
		input_text = self._tb_input.toPlainText()
		output_text = self._tb_output.toPlainText()

		self._tb_output.setText(str(input_text))
		self._tb_input.setText(str(output_text))


if __name__=='__main__':

	app = qt.QApplication([])
	window = qt.QFrame()

	gui = RSAGui()
	gui.init()

	window = qt.QFrame()
	window.resize(700, 500)
	window.setLayout(gui)
	
	window.show()

	app.exec_()