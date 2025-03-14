b'$2a$10$Cfi6ZmWwhnsTqhWlh1ICO.mRM3.Ri8jTv0XJOUJmCFjobRx30LuUe'
b'$2a$10$Cfi6ZmWwhnsTqhWlh1ICO.iIVLTc92oO/cFE654CZs9/PBeUvjEdK'
b'$2a$10$Cfi6ZmWwhnsTqhWlh1ICO./.LPWXRAjRgOirPyhyL3oF0Ggf5wRQq'
b'$2a$10$Cfi6ZmWwhnsTqhWlh1ICO.Zt7efl/osZQp0yjv/Pw5AxajZICLiLS'

bcrypt вибрано, бо:
- додаж Salt щоб збільшити 
- вже має спеціальний метод для хешуваття паролів
- годиться для використання у web-застосунках через достатньо високу швидкодію і малі ресурсо-затрати 
- можлива додаткова параметризація використовуючи метод kdf:
    desired_key_bytes − The number of bytes of the derived key.
    rounds − The number of rounds to use in the KDF.
    hash_function − The hash function to use in the KDF. The default is SHA-512.