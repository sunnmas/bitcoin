require 'ecdsa' #elliptic curves digital signing algorithm
require 'digest'
require 'securerandom'

class Keys
	# Сгенерировать ключи
	def generate private_key = nil #на вход шестнадцатеричную строку
		# В криптовалютах используется так называемая криптография на эллиптических кривых.
		# Если на пальцах, то эллиптическая кривая —  функция, записываемая в
		# виде формы Вейерштрасса: y^2=x^3+ax+b и рассматриваемая на конечном поле.
		# Конечное поле в общей алгебре — поле, состоящее из конечного числа элементов; это число называется порядком поля.
		# Таким образом непрерывное уравнение становится дискретным:
		# y^2 mod p = x^3+ax+b mod p, где p - простое число, являющееся порядком поля.
		# Пары чисел, удовлетворяющие данному уравнению и составляют множество точек эллиптической кривой.
		# Конкретно в блокчейне биткоина используется следующая эллиптическая кривая y^2 = x^3 + 7 над полем порядка
		# p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F = = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
		# Данная кривая известна под названием SECP256k1
		group = ECDSA::Group::Secp256k1

		# Закрытый ключ это случайное число от 1 до p (group.order - порядок поля)
		if private_key != nil
			@private_key = private_key.to_i 16
		else
			@private_key = 1 + SecureRandom.random_number(group.order - 1) #приватник в виде десятичного числа
		end

		#Так же для SECP256k1 определена так называемая base point,
		#обозначаемая G, лежащая на данной кривой. Она нужна для создания публичного ключа.
		#Пусть k — наш приватный ключ, G — base point, тогда публичный ключ o = G * k.
		#То есть, фактически, публичный ключ — это некоторая точка, лежащая на кривой SECP256k1.
		# G - зашита в алгоритмы SECP256k1 и определена как точка с координатами:
		# x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
		# y = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
		# group.generator - получаем точку джи и умножаем ее на приватник 
		@public_key = group.generator.multiply_by_scalar @private_key

		# Адрес вычисляется по следующиму алгоритму:
		# SHA256 и RIPEMD160 - известные алгоритмы подсчета хешей
		# BASE58 перекодировка в формат base 58
		@address = Digest::SHA2.hexdigest [pub].pack('H*')
		@address = Digest::RMD160.hexdigest [@address].pack('H*')
		@hash160_public_key = @address
		chksum = Digest::SHA256.hexdigest ['00'+@address].pack('H*')
		chksum = Digest::SHA256.hexdigest [chksum].pack('H*')
		chksum = chksum[0..7]
		@address = ('00'+@address+chksum).upcase
	end

	# Показать закрытый ключ
	def priv opts
		priv_s = @private_key.to_s(16)
		if opts[:hex] #приватник в виде шестнадцатеричного числа
			return priv_s.upcase
		elsif opts[:wif]
			chksum = Digest::SHA256.hexdigest ['80'+priv_s].pack('H*')
			chksum = Digest::SHA256.hexdigest [chksum].pack('H*')
			chksum = chksum[0..7]
			wif = ('80'+priv_s+chksum).to_i 16
			wif = base58 wif
			return wif
		end
		return priv_s.upcase
	end

	# Показать открытый ключ в сжатом и несжатом формате
	def pub opts = {:compressed => false}
		# По сути открытый ключ это точка на эллиптической кривой.
		# Мы можем удалить одну координату оставив только ее знак, т.о. сократив запись.
		# Зная уравнение кривой всегда можно восстановить вторую координату.
		# Но у эллиптических кривых, когда речь идет о функции над конечным полем,
		# можно воспользоваться следующим свойством:
		# если для Х координаты существуют решения уравнения,
		# то одна из точек будет иметь четную Y координату, а вторая — нечетную.
		# Таким образом краткая запись открытого ключа
		# 0x02 координатаХ_hex, если Y - четная, либо
		# 0x03 координатаX_hex, если Y - нечетная
		if opts[:compressed]
			o1 = "02#{@public_key.x.to_s(16).upcase}" if @public_key.y.even? 
			o1 = "03#{@public_key.x.to_s(16).upcase}" if @public_key.y.odd?
			return o1
		elsif opts[:as_point]
			return @public_key
		else
			return "04#{@public_key.x.to_s(16).upcase}#{@public_key.y.to_s(16)}".upcase
		end
	end

	def hash160_pub
		return @hash160_public_key
	end

	def address opts = {:b58 => false}
		if opts[:b58]
			return '1'+base58(@address.to_i 16)
		else
			return @address
		end
	end
private
	def base58 x
		alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".chars
		''.tap do |base58_val|
			while x > 0
				x, mod = x.divmod(58)
				base58_val.prepend alphabet[mod]
			end
		end
	end
end

#Проверка правильности генерации адреса:
#https://brainwalletx.github.io/#sign

key = Keys.new
key.generate
puts key.priv wif: true
puts key.pub compressed: true
puts key.address b58: true