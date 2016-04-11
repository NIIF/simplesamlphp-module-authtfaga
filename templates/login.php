<?php

$this->includeAtTemplateBase('includes/header.php');
$this->data['header'] = $this->t('{authtfaga:login:authentication}');
?>

<?php if ($this->data['errorcode'] !== NULL) :?>
	<div style="border-left: 1px solid #e8e8e8; border-bottom: 1px solid #e8e8e8; background: #f5f5f5">
		<img src="/<?php echo $this->data['baseurlpath']; ?>resources/icons/experience/gtk-dialog-error.48x48.png" style="float: left; margin: 15px " />
		<h2><?php echo $this->t('{login:error_header}'); ?></h2>
		<p><b><?php echo $this->t('{authtfaga:errors:title_' . $this->data['errorcode'] . '}'); ?></b></p>
		<p><?php echo $this->t('{authtfaga:errors:descr_' . $this->data['errorcode'] . '}'); ?></p>
	</div>
<?php endif; ?>

<form action="?" method="post" name="f" id="form">
<?php if ( $this->data['todo'] == 'choose2enable' ) : ?>
	<h2><?php echo $this->t('{authtfaga:login:2factor_title}')?></h2>
	<div class="loginbox">
		<p class="logintitle"><?php echo $this->t('{authtfaga:login:chooseOTP}')?></p>
        <p>
        	<input type="radio" name="setEnable2f" value="1" /> <?php echo $this->t('{authtfaga:login:yes}')?>
        	<input type="radio" name="setEnable2f" value="0" /> <?php echo $this->t('{authtfaga:login:no}')?>
        	<input class="submitbutton" type="submit" tabindex="2" name="submit" value="<?php echo $this->t('{authtfaga:login:next}')?>" />
        </p>
	</div>

<?php elseif ( $this->data['todo'] == 'generateGA' ) : ?>
	<h2><?php echo $this->t('{authtfaga:login:2factor_title}')?></h2>
	<div class="loginbox">	
		<p class="logintitle"><?php echo $this->t('{authtfaga:login:qrcode}')?></p>
		<p><img src="<?=$this->data['qrcode'];?>" /></p>
        <p><input id="otp" class="yubifield" type="text" tabindex="1" name="otp" /></p>
        <p><input id="submit" class="submitbutton" type="submit" tabindex="2" name="submit" value="<?php echo $this->t('{authtfaga:login:next}')?>"/></p>
	</div>

<?php elseif ( $this->data['todo'] == 'loginOTP' ) : ?>
	<h2><?php echo $this->t('{authtfaga:login:2factor_login}')?></h2>
	<div class="loginbox">
		<p class="logintitle">
			<?php echo $this->t('{authtfaga:login:verificationcode}')?> 
			<input id="otp" class="yubifield" type="text" tabindex="1" name="otp" />
			<input id="submit" class="submitbutton" type="submit" tabindex="2" name="submit" value="<?php echo $this->t('{authtfaga:login:next}')?>"/>
		</p>
	</div>

<?php endif ; ?>

<?php
foreach ($this->data['stateparams'] as $name => $value) {
	echo('<input type="hidden" name="' . htmlspecialchars($name) . '" value="' . htmlspecialchars($value) . '" />');
}
?>

</form>

<?php
$this->includeAtTemplateBase('includes/footer.php');
?>
