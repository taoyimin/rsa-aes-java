/**
 * @author Taoyimin
 * @create 2019 05 07 20:39
 */
public class Config {
    public static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    //必须是PKCS8格式
    public static final String CLIENT_PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAO/8ucCgOTJ7DCPC" +
            "rCCL1VKDnUX61QnxwbAvpGp1/lletEIcjUouM7F0VvMHzViNLvpw7N7NBHPa+5gO" +
            "js68t9hKMUh+a6RTE34SWIqSDRPCzDKVWugsFb04o3vRl3rZ1z6B+QDdW7xwOhEr" +
            "PPoEqmjjIOjQPcU6xs0SPzSimOa1AgMBAAECgYAO5m0OBaSnerZNPhf7yVLMVbmd" +
            "D67MeEMjUkHuDjdlixi8BhPLqESzXtrLKg/Y0KM7D2nVh3sgSldWoIjDUzpCx8Z2" +
            "yHLU1K2wakMdBgEF3xeJPxxZRpP+earl0SyLTA4hMxl48uAjn/mkPgzoMgQkqyQz" +
            "5HOWjjsCLJFyEvqmoQJBAP5cBk0KXpHnCMgOupbi/pXDyaF1o+dCE97GaEdrV/0P" +
            "uwDfYDYfY3wzd1QM7C4b4MmE+SNVpC0W9PyaMONJlN0CQQDxiPiGdwX9actMNJea" +
            "JZ+k3BjCN+mM6Px7j/mtYcXWNZkyCXSXUBI62drZ0htenrh2qwichMlMgNJClvG6" +
            "Gu+5AkEA30R7q2gstrkrNh/nnMZHXcJr3DPc2QNhWayin/4TT+hc51krpJZMxxqN" +
            "5dMqBRcnavwzi9aCs6lxBcF6pCdUaQJANhd7uPls4PzRZ6abkQz9/LjB3rUQ29rN" +
            "uIpc2yR7XuawAVG2x7BJ9N4XMhLoyD75hrH1AsCGKFjtPbZ6OjiQGQJAF2DbIodC" +
            "uYb6eMZ8ux1Ab0wBEWWc5+iGgEVBNh22uZ/klE1/C0+KKzZhqgzaA/vPapq6dhuJ" +
            "sNXlJia10PwYrQ==";

    public static final String CLIENT_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDv/LnAoDkyewwjwqwgi9VSg51F" +
            "+tUJ8cGwL6Rqdf5ZXrRCHI1KLjOxdFbzB81YjS76cOzezQRz2vuYDo7OvLfYSjFI" +
            "fmukUxN+EliKkg0TwswylVroLBW9OKN70Zd62dc+gfkA3Vu8cDoRKzz6BKpo4yDo" +
            "0D3FOsbNEj80opjmtQIDAQAB";

    public static final String SERVER_PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPGkxlAJPKR3BRxT\n" +
            "PIeB3pDv117j8XbpuEik5UIOlY3GUtAV1sad5NNDUAnP/DB80yAQ8ycm9Xdkutuo" +
            "f25Xlb7w0bRQNpfJlijx9eF8PsB6t63r8KAfWJlqbNHgN8AMK9P5XzVyN4YiEnUl" +
            "Jh/EYiwLiYzflNnmnnfRrI4nUo8fAgMBAAECgYEAvwTxm81heeV4Tcbi33/jUBG4" +
            "4BMzCzyA6DQp4wkiYju3tTS+Xq3seLEKcWdPxYi3YO7lODsM6j/fksrlSXXFMe1i" +
            "ZAF3FNuDVZPz2zdFYS8vh6kdlDHMJAUnU/POMMWJ880MQDtkwTuzH8Tao8OKcAP4" +
            "kc0QuG00wOrmuE+5gZECQQD9bqZkJsN+tj3+pxs57azy6B6gOqgm54/ujB+u63XU" +
            "rO9Sf57asgF4OfUFltaVhjlUMSrWcgp6f4HSy7hBSKJpAkEA9BeML5iDIHOgTIws" +
            "+ID55ELbzO7A/YtcYnUU09mkKCdonMXbXke+EhLApf5vX9ZmreoEfJCdsTnMEcQi" +
            "fkjkRwJBALpf2TXl2/cfhs/zjG45f+rTEVK8UFTsDklb+yDkQC87TnTZLbWfGr2T" +
            "wcFugDhOEXL9BYfXLiWQB6VB9Crug6ECQGEmTiFTbj0oSBCvaeauTsdO5PS3whAn" +
            "u2lkeBmpcfCZXsWm6hyoKTpARHTMw789Mjjd/1Mkq96xxkr76U6h7FkCQHRc2elg" +
            "Dh84wqHIptwa+moosVvd7aSzktuOB4CQRO10qKkSHVFuI+sl47A4KGzH/nX9ydUm" +
            "tpsTnQAlXwBczd4=";

    public static final String SERVER_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxpMZQCTykdwUcUzyHgd6Q79de" +
            "4/F26bhIpOVCDpWNxlLQFdbGneTTQ1AJz/wwfNMgEPMnJvV3ZLrbqH9uV5W+8NG0" +
            "UDaXyZYo8fXhfD7Aeret6/CgH1iZamzR4DfADCvT+V81cjeGIhJ1JSYfxGIsC4mM" +
            "35TZ5p530ayOJ1KPHwIDAQAB";
}
