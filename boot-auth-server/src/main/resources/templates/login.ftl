<!doctype html>
<html class="no-js" lang="">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title></title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="apple-touch-icon" href="apple-touch-icon.png">

    <link rel="stylesheet" href="css/bootstrap.min.css">
    <style>

        * {
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            outline: none;
        }

        .form-control {
            position: relative;
            font-size: 16px;
            height: auto;
            padding: 10px;
        @include box-sizing(border-box);

        &:focus {
             z-index: 2;
         }
        }

        body {
            background: url(http://i.imgur.com/GHr12sH.jpg) no-repeat center center fixed;
            -webkit-background-size: cover;
            -moz-background-size: cover;
            -o-background-size: cover;
            background-size: cover;
        }

        .login-form {
            margin-top: 60px;
        }

        form[role=login] {
            color: #5d5d5d;
            background: #f2f2f2;
            padding: 26px;
            border-radius: 10px;
            -moz-border-radius: 10px;
            -webkit-border-radius: 10px;
        }
        form[role=login] img {
            display: block;
            margin: 0 auto;
            margin-bottom: 35px;
        }
        form[role=login] input,
        form[role=login] button {
            font-size: 18px;
            margin: 16px 0;
        }
        form[role=login] > div {
            text-align: left;
        }

        .form-links {
            text-align: center;
            margin-top: 1em;
            margin-bottom: 50px;
        }
        .form-links a {
            color: #fff;
        }
    </style>
    <link rel="stylesheet" href="css/bootstrap-theme.min.css">
    <link rel="stylesheet" href="css/main.css">

    <script src="js/vendor/modernizr-2.8.3-respond-1.4.2.min.js"></script>
</head>
<body>
<div class="container">
    <div class="row" id="pwd-container">
        <div class="col-md-4"></div>

        <div class="col-md-4">
            <section class="login-form">
                <form method="post" action="login" role="login">

                    <input  id="username" name="username" type="text" placeholder="Username" required class="form-control input-lg"/>

                    <input type="password" placeholder="Password" class="form-control input-lg" id="password" name="password"  required="" />


                    <input type="hidden"
                           name="${_csrf.parameterName}"
                           value="${_csrf.token}" />

                    <button type="submit" name="go" class="btn btn-lg btn-primary btn-block">Sign in</button>
                    <div>
                        <h3>Valid accounts</h3>
                        <ul class="list-group">
                            <li class="list-group-item">
                                <span class="glyphicon glyphicon-user" aria-hidden="true"></span>
                                <strong>reader : reader</strong>
                                <div class="pull-right">
                                    <span class="glyphicon glyphicon-ok" aria-hidden="true"></span> Permissoins.
                                </div>
                            </li>
                            <li class="list-group-item">
                                <span class="glyphicon glyphicon-user" aria-hidden="true"></span>
                                <strong>guest : guest</strong>
                                <div class="pull-right">
                                    <span class="glyphicon glyphicon-remove" aria-hidden="true"></span> Permissoins.
                                </div>
                            </li>
                        </ul>
                    </div>

                </form>


            </section>
        </div>

        <div class="col-md-4"></div>


    </div>



</div> <!-- /container -->




<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script>window.jQuery || document.write('<script src="js/vendor/jquery-1.11.2.min.js"><\/script>')</script>

<script src="js/vendor/bootstrap.min.js"></script>

<script src="js/main.js"></script>


</body>
</html>


