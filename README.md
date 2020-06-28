# A5/A5X checkm8

[checkm8](https://github.com/axi0mX/ipwndfu/blob/master/checkm8.py) port for S5L8940X/S5L8942X/S5L8945X based on Arduino and MAX3421E-based USB Host Shield

## Building

Follow the instructions [here](https://github.com/DSecurity/checkm8-arduino#building). Note that the patch for [USB Host Library Rev. 2.0](https://github.com/felis/USB_Host_Shield_2.0) is different.

### USB Host Library Rev. 2.0 installation and patching

```
cd path/to/Arduino/libraries
git clone https://github.com/felis/USB_Host_Shield_2.0
cd USB_Host_Shield_2.0
git checkout cd87628af4a693eeafe1bf04486cf86ba01d29b8
git apply path/to/usb_host_library.patch
```

### SoC selection

Before using the exploit change this line in the beginning of `checkm8-a5.ino` with target SoC CPID:

```
#define A5_8942
```

## S5L8940X/S5L8942X/S5L8945X-specific exploitation notes

*[This article](https://habr.com/ru/company/dsec/blog/472762/) may be helpful for better understanding.*

### 1. `HOST2DEVICE` control request without data phase processing

In newer SoCs this request is processed as follows. Note that there are different cases for `request_handler_ret == 0` and `request_handler_ret > 0`:

```c
void __fastcall usb_core_handle_usb_control_receive(void *ep0_rx_buffer, __int64 is_setup, __int64 data_rcvd, bool *data_phase)
{
  ...
  // get interface control request handler
  request_handler = ep.registered_interfaces[(unsigned __int16)setup_request.wIndex]->request_handler;
  if ( !request_handler )
    goto error_handling;
  // call to interface control request handler
  // set global buffer pointer
  request_handler_ret = request_handler(&g_setup_request, &ep0_data_phase_buffer);
  if ( !(g_setup_request.bmRequestType & 0x80000000) )
  {
    // HOST2DEVICE
    if ( request_handler_ret >= 1 )
    {
      // set global data phase length and ifnum
      ep0_data_phase_length = request_handler_ret; 
      ep0_data_phase_if_num = intf_num;
      goto continue;
    }
    if ( !request_handler_ret )
    {
      // acknowledge transaction with zlp, do not touch global state
      usb_core_send_zlp();
      goto continue;
    }
  ...
}
```

But in our target SoCs this request is processed slightly different:

```c
unsigned int __fastcall usb_core_handle_usb_control_receive(unsigned int rx_buffer, int is_setup, unsigned int data_received, int *data_phase)
{
  ...
  if ( is_setup )
  {
    v11 = memmove((unsigned int)&g_setup_packet, rx_buffer, 8);
    if ( g_setup_packet.bmRequestType & 0x60 )
    {
      if ( (g_setup_packet.bmRequestType & 0x60) != 0x20
        || (g_setup_packet.bmRequestType & 0x1F) != 1
        || (v29 = LOBYTE(g_setup_packet.wIndex) | (HIBYTE(g_setup_packet.wIndex) << 8), v29 >= ep_size)
        || (request_handler = *(int (__fastcall **)(setup_req *, _DWORD *))(ep_array[LOBYTE(g_setup_packet.wIndex) | (HIBYTE(g_setup_packet.wIndex) << 8)]
                                                                          + 32)) == 0
        || (request_handler_ret = request_handler(&g_setup_packet, &ep0_data_phase_buffer), request_handler_ret < 0) )
      {
        // error handling
        rx_buffer = sub_2E7C(0x80, 1);
        v10 = 0;
        goto LABEL_103;
      }
      // if request_handler_ret >= 0, then data phase length will be touched anyway
      ep0_data_phase_length = request_handler_ret;
      ep0_data_phase_if_num = v29;
      *data_phase = 1;
      goto continue;
    }
  ...
}
```

So, if we send any `HOST2DEVICE` control request without data phase, then `ep0_data_phase_length` will be reset to zero. Because of this we can't use `ctrlReq(0x21,4,0)` to reenter `DFU`. But there is another way to reenter `DFU`:

1. `ctrlReq(bmRequestType = 0x21,bRequest = 1,wLength = 0x40)` with any data
2. `ctrlReq(0x21,1,0)`
3. `ctrlReq(0xa1,3,1)`
4. `ctrlReq(0xa1,3,1)`
5. `USB` bus reset

So, to be able to write to the freed `io_buffer`, we do steps 1-4, then send an incomplete `HOST2DEVICE` control transaction to set global state, then trigger bus reset. This algorithm is fully described [here](https://gist.github.com/littlelailo/42c6a11d31877f98531f6d30444f59c4) by [littlelailo](https://github.com/littlelailo).

But, if we use any normal OS with default USB stack for exploitation, then we can't avoid standard device requests (e.g. `SET_ADDRESS`, see [this](https://www.beyondlogic.org/usbnutshell/usb6.shtml) for more info) sent by OS before we can work with device. Because of it in our PoC we use `Arduino` and `MAX3421E` to control early initialization of USB.

### 2. Zero length packet processing

In newer SoCs data packets are processed as follows. Note that in case of zero length packet processing is not performed.

```c
void __fastcall usb_core_handle_usb_control_receive(void *ep0_rx_buffer, __int64 is_setup, __int64 data_rcvd, bool *data_phase)
{
  ...
  if ( !(is_setup & 1) )
  {
    if ( !(_DWORD)data_rcvd ) // check for zero length packet
      return;
    if ( ep0_data_phase_rcvd + (unsigned int)data_rcvd <= ep0_data_phase_length )
    {
      if ( ep0_data_phase_length - ep0_data_phase_rcvd >= (unsigned int)data_rcvd )
        to_copy = (unsigned int)data_rcvd;
      else
        to_copy = ep0_data_phase_length - ep0_data_phase_rcvd;
      memmove(ep0_data_phase_buffer, ep0_rx_buffer, to_copy);// copy received data to IO-buffer
      ep0_data_phase_buffer += (unsigned int)to_copy;// update global buffer pointer
      ep0_data_phase_rcvd += to_copy;           // update received counter
      *data_phase = 1;
      // stop transfer if received expected number of bytes
      // or received less then 0x40 bytes packet
      if ( (_DWORD)data_rcvd == 0x40 )
        end_of_transfer = ep0_data_phase_rcvd == ep0_data_phase_length;
      else
        end_of_transfer = 1;
  ...
}
```

But in our target SoCs zero length packets are processed in the same way as non-zero length packets.


```c
unsigned int __fastcall usb_core_handle_usb_control_receive(unsigned int rx_buffer, int is_setup, unsigned int data_received, int *data_phase)
{
  ...
  // data packet processing starts here
  rx_buffer = ep0_data_phase_buffer;
  if ( !ep0_data_phase_buffer )
    return rx_buffer;
  if ( data_received + ep0_data_phase_rcvd > ep0_data_phase_length )
  {
    rx_buffer = sub_2E7C(128, 1);
reset_global_state:
    v10 = 0;
    ep0_data_phase_rcvd = 0;
    ep0_data_phase_length = 0;
    ep0_data_phase_buffer = 0;
    ep0_data_phase_if_num = -2;
LABEL_103:
    *v6 = v10;
    return rx_buffer;
  }
  if ( data_received >= ep0_data_phase_length - ep0_data_phase_rcvd )
    v7 = ep0_data_phase_length - ep0_data_phase_rcvd;
  else
    v7 = data_received;
  memmove(ep0_data_phase_buffer, rx_buffer_1, v7);
  end_of_transfer = data_received_1 != 0x40;  // in case of zero length packet `end_of_transfer` will be `true`
                                              // and global state will be reseted
  ep0_data_phase_buffer += v7;
  ep0_data_phase_rcvd += v7;
  rx_buffer = ep0_data_phase_rcvd;
  *v6 = 1;
  if ( rx_buffer == ep0_data_phase_length )
    end_of_transfer = 1;
  if ( end_of_transfer )
  {
    if ( (int)ep0_data_phase_if_num >= 0 && ep0_data_phase_if_num < ep_size )
    {
      v9 = *(void (**)(void))(ep_array[ep0_data_phase_if_num] + 36);
      if ( v9 )
      {
        v9();
        rx_buffer = usb_core_send_zlp();
      }
    }
    goto reset_global_state;
  }
  return rx_buffer;
}
```

As in the previous case, if we use normal OS with default USB stack, we can't avoid sending of zero length packets in status phase of standard device USB controll requests.

## Important notes

* Do not use any cables with embedded USB hubs (DCSD/Kong/Kanzi/etc.), as it might prevent a device from being recognized by the program. Normal USB-cables will do the trick just fine
* This exploit demotes your device by default, so SWD-debugging will be available. But that also makes your device use development KBAG when decrypting Image3s. Keep that in mind if you're going to use this to decrypt firmware components

## Authors

* [a1exdandy](https://github.com/a1exdandy)
* [nyan_satan](https://github.com/NyanSatan)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
